#!/usr/bin/env bash
# End-to-end HTTP acceptance on a disposable published-v3 installation.
# Called by test-update-package.sh after ZIP extraction, before any DDL upgrade.
set -euo pipefail
[[ $# -eq 4 ]] || { echo "Usage: $0 <site> <temp> <from> <to>" >&2; exit 2; }
site="$1"; tmp="$2"; from="$3"; to="$4"
[[ "$from" == 3.* && "$to" == 3.* && -f "$site/artisan" && -f "$site/public/update/index.php" ]] || exit 2
port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
base="http://127.0.0.1:$port"
proto="X-Forwarded-Proto: https"
cat > "$tmp/router.php" <<'PHP'
<?php
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?: '/';
$file = rtrim($_SERVER['DOCUMENT_ROOT'], '/').$path;
if ($path !== '/' && (is_file($file) || is_dir($file))) return false;
require $_SERVER['DOCUMENT_ROOT'].'/index.php';
PHP
(cd "$site" && exec php -S "127.0.0.1:$port" -t public "$tmp/router.php") >"$tmp/http.log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true' EXIT

ready=0
for i in {1..50}; do
  if curl -fsS --max-time 2 "$base/up" >/dev/null 2>&1; then ready=1; break; fi
  sleep 0.2
done
[[ "$ready" == 1 ]] || { echo "Gateway HTTP fixture did not start" >&2; tail -n 8 "$tmp/http.log" >&2; exit 1; }

csrf_from() { grep -o 'name="_token" value="[^"]*"' "$1" | head -n 1 | sed -E 's/.*value="([^"]*)"/\1/'; }
login() {
  local email="$1" jar="$2" tok code
  code="$(curl -sS --max-time 20 -c "$jar" -b "$jar" -H "$proto" -o "$tmp/login.html" -w '%{http_code}' "$base/admin/login")"
  [[ "$code" == 200 ]] || { echo "Login GET $code" >&2; exit 1; }
  tok="$(csrf_from "$tmp/login.html")"
  [[ -n "$tok" ]] || { echo "Login CSRF missing" >&2; exit 1; }
  code="$(curl -sS --max-time 20 -c "$jar" -b "$jar" -H "$proto" -o "$tmp/login-post.html" -w '%{http_code}' \
     --data-urlencode "_token=$tok" --data-urlencode "email=$email" \
     --data-urlencode 'password=CorrectHorse!234' "$base/admin/login")"
  [[ "$code" == 302 ]] || { echo "Login POST $code" >&2; exit 1; }
}
admin_cookies() {
  awk 'BEGIN{sep=""} /^#/ && $0 !~ /^#HttpOnly_/ {next} NF>=7 && $6 != "mcp_gateway_update_session" {
      printf "%s%s=%s",sep,$6,$7;sep="; "
    } END {print ""}' "$1"
}
assert_no_stage() {
  [[ ! -e "$site/storage/app/private/update-state.json" && ! -e "$site/storage/framework/down" ]] || {
    echo "Denied HTTP request modified update state" >&2; exit 1;
  }
  [[ "$(tr -d '[:space:]' < "$site/VERSION")" == "$from" ]]
}
guest="$(curl -sS --max-time 20 -H "$proto" -D "$tmp/guest.headers" -o /dev/null -w '%{http_code}' "$base/update/")"
[[ "$guest" == 302 ]] || { echo "Guest update: $guest" >&2; exit 1; }
grep -qi '^Location: .*/admin/login' "$tmp/guest.headers"
login 'gateway-qa-operator@example.test' "$tmp/operator.cookies"
operator="$(curl -sS --max-time 20 -c "$tmp/operator.cookies" -b "$tmp/operator.cookies" -H "$proto" \
  -D "$tmp/denied.headers" -o /dev/null -w '%{http_code}' "$base/update/")"
[[ "$operator" == 403 ]] || { echo "Operator update: $operator" >&2; exit 1; }
! grep -qi '^Set-Cookie: mcp_gateway_update_session=' "$tmp/denied.headers"
assert_no_stage
login 'gateway-qa-disabled@example.test' "$tmp/disabled.cookies"
disabled="$(curl -sS --max-time 20 -c "$tmp/disabled.cookies" -b "$tmp/disabled.cookies" -H "$proto" \
  -o /dev/null -w '%{http_code}' "$base/update/")"
[[ "$disabled" == 302 || "$disabled" == 403 ]] || { echo "Disabled Owner update: $disabled" >&2; exit 1; }
assert_no_stage
login 'gateway-qa-owner@example.test' "$tmp/owner.cookies"
# Verify the real database row is checked, rather than a stale authenticated session.
(
 cd "$site"
 php -r 'require "vendor/autoload.php";$a=require "bootstrap/app.php";
 $a->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
 Illuminate\Support\Facades\DB::table("users")->where("email","gateway-qa-owner@example.test")->update(["role"=>"operator"]);'
)
stale="$(curl -sS --max-time 20 -c "$tmp/owner.cookies" -b "$tmp/owner.cookies" -H "$proto" \
  -o /dev/null -w '%{http_code}' "$base/update/")"
[[ "$stale" == 403 ]] || { echo "Stale Owner update: $stale" >&2; exit 1; }
assert_no_stage
(
 cd "$site"
 php -r 'require "vendor/autoload.php";$a=require "bootstrap/app.php";
 $a->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
 Illuminate\Support\Facades\DB::table("users")->where("email","gateway-qa-owner@example.test")->update(["role"=>"owner"]);'
)
preflight="$(curl -sS --max-time 25 -c "$tmp/owner.cookies" -b "$tmp/owner.cookies" -H "$proto" \
  -D "$tmp/preflight.headers" -o "$tmp/preflight.html" -w '%{http_code}' "$base/update/")"
[[ "$preflight" == 200 ]] || { echo "Owner preflight: $preflight" >&2; exit 1; }
grep -F "Installed:</strong> $from" "$tmp/preflight.html" >/dev/null
grep -F "Target:</strong> $to" "$tmp/preflight.html" >/dev/null
csrf="$(csrf_from "$tmp/preflight.html")"
cookie="$(grep -i '^Set-Cookie: mcp_gateway_update_session=' "$tmp/preflight.headers" | tail -n 1 | sed -E 's/^[^=]+=([^;]+).*/\1/' | tr -d '\r')"
[[ -n "$csrf" && "$cookie" =~ ^[a-f0-9]{64}$ ]] || { echo "Owner capability/CSRF not issued" >&2; exit 1; }
for flag in 'secure' 'HttpOnly' 'SameSite=Strict' 'path=/update/'; do
  grep -i '^Set-Cookie: mcp_gateway_update_session=' "$tmp/preflight.headers" | grep -Fi "$flag" >/dev/null || {
    echo "Updater cookie missing $flag" >&2; exit 1;
  }
done
base_cookies="$(admin_cookies "$tmp/owner.cookies")"
cookies="$base_cookies; mcp_gateway_update_session=$cookie"
bad_csrf="$(curl -sS --max-time 20 -H "$proto" -H "Cookie: $cookies" \
  --data-urlencode '_token=invalid-csrf' --data-urlencode 'action=start' \
  -o /dev/null -w '%{http_code}' "$base/update/")"
[[ "$bad_csrf" == 419 ]] || { echo "Invalid CSRF accepted: $bad_csrf" >&2; exit 1; }
assert_no_stage
missing_cookie="$(curl -sS --max-time 20 -H "$proto" -H "Cookie: $base_cookies" \
  --data-urlencode "_token=$csrf" --data-urlencode 'action=start' \
  -o /dev/null -w '%{http_code}' "$base/update/")"
[[ "$missing_cookie" == 409 ]] || { echo "Missing cookie accepted: $missing_cookie" >&2; exit 1; }
assert_no_stage
stage="$(curl -sS --max-time 115 -H "$proto" -H "Cookie: $cookies" \
  --data-urlencode "_token=$csrf" --data-urlencode 'action=start' \
  -D "$tmp/stage.headers" -o "$tmp/stage.html" -w '%{http_code}' "$base/update/")"
[[ "$stage" == 303 ]] || { echo "Stage HTTP $stage" >&2; tail -n 12 "$tmp/http.log" >&2; exit 1; }
grep -qi '^Location: /update/' "$tmp/stage.headers"
[[ "$(tr -d '[:space:]' < "$site/VERSION")" == "$to" ]]
[[ -e "$site/storage/app/private/update-state.json" ]]

# Exercise the updater recovery fallback with the actual v3 Laravel DB,
# intentionally omitting the optional external ledger-reader callback.
(
 cd "$site"
 php -r 'require "vendor/autoload.php"; $a=require "bootstrap/app.php";
 $a->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
 require "update/WebUpdater.php";
 $u=new McpGatewayUpdate\WebUpdater($argv[1],$argv[1]."/update");
 $r=$u->preMigrationRecoveryStatus();
 if (($r["ready"]??null)!==true || $r["phase"]!=="files-replaced") {
   throw new RuntimeException("Default migration ledger reader failed");
 }' "$site"
)
get="$(curl -sS --max-time 20 -H "$proto" -H "Cookie: $cookies" -o "$tmp/resume.html" -w '%{http_code}' "$base/update/")"
[[ "$get" == 200 ]] || { echo "Resume GET $get" >&2; exit 1; }
continuation="$(grep -o 'name="continuation" value="[a-f0-9]*"' "$tmp/resume.html" | head -n 1 | sed -E 's/.*value="([a-f0-9]*)"/\1/')"
[[ "$continuation" =~ ^[a-f0-9]{64}$ ]] || { echo "Browser continuation missing" >&2; exit 1; }
grep -F 'id="continue-update"' "$tmp/resume.html" >/dev/null
grep -F "fetch('/update/'" "$tmp/resume.html" >/dev/null
replay="$(curl -sS --max-time 20 -H "$proto" -H "Cookie: $cookies" \
  --data-urlencode "_token=$csrf" --data-urlencode 'action=start' \
  -o /dev/null -w '%{http_code}' "$base/update/")"
[[ "$replay" == 303 ]] || { echo "Stage replay HTTP $replay" >&2; exit 1; }
unbound="$(curl -sS --max-time 20 -H "$proto" --data-urlencode 'action=finish' \
  --data-urlencode "continuation=$continuation" -o /dev/null -w '%{http_code}' "$base/update/")"
[[ "$unbound" == 403 ]] || { echo "Unbound Finish HTTP $unbound" >&2; exit 1; }
wrong="$(curl -sS --max-time 20 -H "$proto" -H "Cookie: $cookies" \
  --data-urlencode 'action=finish' --data-urlencode 'continuation=invalid' \
  -o /dev/null -w '%{http_code}' "$base/update/")"
[[ "$wrong" == 303 ]] || { echo "Wrong continuation HTTP $wrong" >&2; exit 1; }
# Simulate a crash after migration could have started, then restore the
# unchanged pre-migration state in the disposable test before real Finish.
state="$site/storage/app/private/update-state.json"
cp "$state" "$tmp/saved-state.json"
php -r '$p=$argv[1];$s=json_decode(file_get_contents($p),true,512,JSON_THROW_ON_ERROR);
 $s["phase"]="migrate";$s["migration_started"]=true;
 file_put_contents($p,json_encode($s,JSON_THROW_ON_ERROR));' "$state"
interrupted="$(curl -sS --max-time 20 -H "$proto" -H "Cookie: $cookies" \
  -o "$tmp/interrupted.html" -w '%{http_code}' "$base/update/")"
[[ "$interrupted" == 503 ]] || { echo "Interrupted update HTTP $interrupted" >&2; exit 1; }
grep -F 'MCP Gateway Postflight Status Unverified' "$tmp/interrupted.html" >/dev/null
grep -F 'Do not repeat migrations' "$tmp/interrupted.html" >/dev/null
cp "$tmp/saved-state.json" "$state"
finish="$(curl -sS --max-time 115 -H "$proto" -H "Cookie: $cookies" \
  --data-urlencode 'action=finish' --data-urlencode "continuation=$continuation" \
  -o "$tmp/finish.html" -w '%{http_code}' "$base/update/")"
[[ "$finish" == 200 ]] || { echo "Finish HTTP $finish" >&2; tail -n 14 "$tmp/http.log" >&2; exit 1; }
grep -F 'MCP Gateway Updated' "$tmp/finish.html" >/dev/null
grep -F "MCP Gateway $from → $to" "$tmp/finish.html" >/dev/null
health="$(curl -sS --max-time 20 -H "$proto" -o /dev/null -w '%{http_code}' "$base/up")"
[[ "$health" == 200 ]] || { echo "Post-upgrade /up HTTP $health" >&2; exit 1; }
echo "PASS: v3 authenticated HTTP update, guest/role/stale denial, CSRF, cookies, Stage 303, browser continuation, replay, recovery, Finish, health."
