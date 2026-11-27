<?php

namespace App\Application\Targets;

use Closure;
use phpseclib4\Exception\FileSystemException;
use phpseclib4\Net\SFTP;
use phpseclib4\Net\SFTP\FileType;
use Throwable;

/** Verify one private operation-owned artifact across native exec and SFTP. */
final readonly class SshPrivateArtifactWitness
{
    public function __construct(
        private string $directory,
        private string $marker,
        private string $witness,
        private string $failureCode,
    ) {}

    public function directoryCheck(): string
    {
        $directory = self::quote($this->directory);

        return 'test -d '.$directory.' && test ! -L '.$directory
            .' && test "$(stat -c %a -- '.$directory.')" = 700'
            .' && test "$(stat -c %u -- '.$directory.')" = "$(id -u)"';
    }

    public function shellCheck(): string
    {
        $marker = self::quote($this->directory.'/'.$this->marker);

        return $this->directoryCheck().' && test -f '.$marker.' && test ! -L '.$marker
            .' && test "$(stat -c %a -- '.$marker.')" = 600'
            .' && test "$(stat -c %u -- '.$marker.')" = "$(id -u)"'
            .' && test "$(stat -c %s -- '.$marker.')" = '.strlen($this->witness)
            .' && test "$(cat -- '.$marker.')" = '.self::quote($this->witness);
    }

    /** @return Closure(SFTP, Closure():void):void */
    public function sftpVerifier(): Closure
    {
        return function (SFTP $sftp, Closure $assertAuthority): void {
            $sftp->disableStatCache();
            $path = $this->directory.'/'.$this->marker;
            try {
                $assertAuthority();
                $dir = $sftp->lstat($this->directory);
                $assertAuthority();
                $marker = $sftp->lstat($path);
                $version = $sftp->getNegotiatedVersion();
                $ownerField = $version <= 3 ? 'uid' : 'owner';
                $owner = $dir[$ownerField] ?? null;
                $sameOwner = ($version <= 3 ? is_int($owner) : is_string($owner) && $owner !== '')
                    && $owner === ($marker[$ownerField] ?? null);
                if (($dir['type'] ?? null) !== FileType::DIRECTORY
                    || ($marker['type'] ?? null) !== FileType::REGULAR
                    || ! is_int($dir['mode'] ?? null) || ($dir['mode'] & 0777) !== 0700
                    || ! is_int($marker['mode'] ?? null) || ($marker['mode'] & 0777) !== 0600
                    || ! $sameOwner || ($marker['size'] ?? null) !== strlen($this->witness)) {
                    throw new SshTargetConnectionException($this->failureCode);
                }
                $assertAuthority();
                $contents = $sftp->get($path, null, 0, strlen($this->witness));
                if (! hash_equals($this->witness, (string) $contents)) {
                    throw new SshTargetConnectionException($this->failureCode);
                }
            } catch (SshTargetConnectionException $exception) {
                throw $exception;
            } catch (FileSystemException $exception) {
                throw new SshTargetConnectionException($this->failureCode, [
                    'exception_class' => $exception::class,
                    'source_error_code' => $exception->getCode(),
                    'source_error_message' => $exception->getMessage(),
                ]);
            } catch (Throwable $exception) {
                throw new SshTargetConnectionException($this->failureCode, ['exception_class' => $exception::class]);
            }
        };
    }

    /** POSIX quoting without locale-dependent loss of UTF-8 path bytes. */
    public static function quote(string $value): string
    {
        return "'".str_replace("'", "'\"'\"'", $value)."'";
    }
}
