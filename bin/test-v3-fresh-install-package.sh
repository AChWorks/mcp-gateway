#!/usr/bin/env bash
# Release-gate smoke on the exact unpacked production ZIP and a disposable,
# empty, isolated CI MariaDB database. Never pass an operator/Production DB.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo 'Usage: test-v3-fresh-install-package.sh <deployment ZIP> <package root>' >&2
  exit 2
fi

zip_path="$(realpath "$1")"
package="$2"
# The release gate uses a stable v3.N.N root; PR CI uses an explicitly
# disposable candidate runtime root. Neither path grants deployment access.
if [[ "$package" != 'mcp-gateway-update-test-runtime' ]]; then
  [[ "$package" =~ ^mcp-gateway-v3\.[0-9]+\.[0-9]+(-rc\.[1-9][0-9]*)?$ ]] || {
    echo 'Only v3 release/candidate or the reviewed PR test runtime is accepted.' >&2
    exit 2
  }
fi
for name in V3_RELEASE_TEST_DB_HOST V3_RELEASE_TEST_DB_PORT V3_RELEASE_TEST_DB_DATABASE \
  V3_RELEASE_TEST_DB_USERNAME V3_RELEASE_TEST_DB_PASSWORD; do
  [[ -n "${!name:-}" ]] || { echo "Required disposable test database variable missing: $name" >&2; exit 2; }
done
[[ "${V3_RELEASE_TEST_DB_HOST}" == '127.0.0.1' && "${V3_RELEASE_TEST_DB_DATABASE}" == *_test ]] || {
  echo 'V3 release smoke requires a loopback disposable *_test database; refusing other targets.' >&2
  exit 2
}
[[ -f "$zip_path" ]] || { echo 'Fresh release ZIP not found.' >&2; exit 2; }

temp="$(mktemp -d "${TMPDIR:-/tmp}/gateway-v3-stable-install-XXXXXXXX")"
trap 'rm -rf -- "$temp"' EXIT
unzip -q "$zip_path" -d "$temp"
runtime="$temp/$package"
[[ -f "$runtime/vendor/autoload.php" && -f "$runtime/public/install.php" ]] || {
  echo 'The fresh-install ZIP lacks the deployable installer/vendor.' >&2
  exit 1
}
case "$(tr -d '[:space:]' < "$runtime/VERSION")" in
  3.*) ;;
  *) echo 'The tested runtime is not a clean v3 candidate/release.' >&2; exit 1 ;;
esac

export V3_RELEASE_TEST_RUNTIME="$runtime"
php -r '
$pdo = new PDO(sprintf(
    "mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4",
    getenv("V3_RELEASE_TEST_DB_HOST"), (int) getenv("V3_RELEASE_TEST_DB_PORT"),
    getenv("V3_RELEASE_TEST_DB_DATABASE")
), getenv("V3_RELEASE_TEST_DB_USERNAME"), getenv("V3_RELEASE_TEST_DB_PASSWORD"), [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
]);
$statement = $pdo->prepare("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = ?");
$statement->execute([getenv("V3_RELEASE_TEST_DB_DATABASE")]);
if ((int) $statement->fetchColumn() !== 0) {
    fwrite(STDERR, "Refusing v3 release smoke against a nonempty database.\n");
    exit(1);
}
'
php -r '
$runtime = getenv("V3_RELEASE_TEST_RUNTIME");
require $runtime."/vendor/autoload.php";
$input = [
    "app_url" => "https://release-fixture.example",
    "db_connection" => "mariadb",
    "db_host" => getenv("V3_RELEASE_TEST_DB_HOST"),
    "db_port" => getenv("V3_RELEASE_TEST_DB_PORT"),
    "db_database" => getenv("V3_RELEASE_TEST_DB_DATABASE"),
    "db_username" => getenv("V3_RELEASE_TEST_DB_USERNAME"),
    "db_password" => getenv("V3_RELEASE_TEST_DB_PASSWORD"),
    "admin_name" => "Release Fixture Owner",
    "admin_email" => "release-fixture@example.invalid",
    "admin_password" => "ReleaseFixtureOwner!7091",
    "admin_password_confirmation" => "ReleaseFixtureOwner!7091",
];
$errors = App\Support\SimpleWebInstaller::validateInput($input, "release-fixture.example");
if ($errors) {
    fwrite(STDERR, "Test input rejected: ".implode(",", array_keys($errors))."\n");
    exit(1);
}
$checks = App\Support\SimpleWebInstaller::preflight($runtime, true);
foreach ($checks as $name => $pass) {
    if (! $pass) {
        fwrite(STDERR, "Unpacked release installer preflight failed: ".$name."\n");
        exit(1);
    }
}
App\Support\SimpleWebInstaller::install($runtime, $input);
if (! App\Support\SimpleWebInstaller::isInstalled($runtime)) {
    throw new RuntimeException("Successful release install did not create the marker.");
}
try {
    App\Support\SimpleWebInstaller::install($runtime, $input);
    throw new RuntimeException("Release installer accepted a second initialization.");
} catch (RuntimeException $error) {
    if (! str_contains($error->getMessage(), "already installed")) {
        throw $error;
    }
}
'
(cd "$runtime" && php artisan gateway:check --no-interaction)
php -r '
$root = getenv("V3_RELEASE_TEST_RUNTIME");
$env = file_get_contents($root."/.env");
foreach (["APP_ENV=production", "APP_DEBUG=false", "SESSION_SECURE_COOKIE=true",
    "MCP_BOOTSTRAP_FIXTURE_ENABLED=false", "SSH_FILE_TRANSFER_ENABLED=true"] as $must) {
    if (! str_contains($env, $must)) {
        throw new RuntimeException("Fresh release environment missing a required safe setting: ".$must);
    }
}
foreach ([".env", "storage/app/private/installed",
    "storage/app/private/oauth/private.key"] as $file) {
    $path = $root."/".$file;
    if (! is_file($path)) {
        throw new RuntimeException("Missing private release runtime file: ".$file);
    }
}
$mode = fileperms($root."/.env") & 0777;
if ($mode !== 0600) {
    throw new RuntimeException("Web installer did not restrict private .env to 0600.");
}
$pdo = new PDO(sprintf("mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4",
    getenv("V3_RELEASE_TEST_DB_HOST"), (int) getenv("V3_RELEASE_TEST_DB_PORT"),
    getenv("V3_RELEASE_TEST_DB_DATABASE")),
    getenv("V3_RELEASE_TEST_DB_USERNAME"), getenv("V3_RELEASE_TEST_DB_PASSWORD"),
    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$count = $pdo->query("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()")->fetchColumn();
$migrations = $pdo->query("SELECT COUNT(*) FROM migrations")->fetchColumn();
$ownerQuery = $pdo->prepare("SELECT COUNT(*) FROM users WHERE role = ? AND access_enabled = 1 AND ai_access_enabled = 1");
$ownerQuery->execute(["owner"]);
$owner = $ownerQuery->fetchColumn();
$legacyQuery = $pdo->prepare("SHOW TABLES LIKE ?");
$legacyQuery->execute(["sites"]);
$historic = $legacyQuery->fetchAll();
if ((int) $count !== 46 || (int) $migrations !== 2 || (int) $owner !== 1 || $historic !== []) {
    throw new RuntimeException(sprintf("Invalid installed schema/users: tables=%d migrations=%d owners=%d",
        $count, $migrations, $owner));
}
echo "PASS: packaged v3 fresh installation, 46 tables, 2 migrations, 1 Owner, 0600 private keys, locked reinstall and gateway:check.\n";
'
