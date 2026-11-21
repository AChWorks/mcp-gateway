<?php

namespace App\Infrastructure\Connectors\SshDirect;

use Closure;
use phpseclib4\Common\Functions\Strings;
use phpseclib4\Net\SFTP;
use phpseclib4\Net\SFTP\PacketType;
use phpseclib4\Net\SFTP\StatusCode;
use RuntimeException;

/**
 * Stream bounded SFTP READDIR windows over the existing authenticated SFTP
 * channel. phpseclib 4.0's public rawlist() materializes the entire directory
 * and has no seek/paged API. This narrowly scoped adapter reuses its protocol
 * codec, packet transport, and CLOSE handling instead of opening another SSH
 * connection or relying on a remote shell. The private codec seam is covered
 * by the real OpenSSH fixture and must be revisited on phpseclib upgrades.
 */
final class SftpDirectoryPaginator
{
    /**
     * @return array{items:list<array{name:string,attributes:array<string,mixed>}>,has_more:bool,read:int}
     */
    public function read(SFTP $sftp, string $directory, int $offset, int $limit, int $maxNameBytes): array
    {
        // Only standard SFTP packets, on an already host-key-verified channel.
        // Never leave a handle open across HTTP requests or an exception.
        $reader = Closure::bind(function (string $dir, int $skip, int $take, int $nameBudget): array {
            $this->precheck();
            $dir = $this->realpath($dir.'/');
            $this->send_sftp_packet(PacketType::OPENDIR, Strings::packSSH2('s', $dir));
            $response = $this->get_sftp_packet_or_error([PacketType::HANDLE, PacketType::STATUS]);
            $handle = substr($response, 4);

            $items = [];
            $namesSize = 0;
            $seen = 0;
            $hasMore = false;
            try {
                while (true) {
                    $this->send_sftp_packet(PacketType::READDIR, Strings::packSSH2('s', $handle));
                    $reply = $this->get_sftp_packet_or_error([PacketType::NAME, PacketType::STATUS], StatusCode::EOF);
                    if ($this->packet_type === PacketType::STATUS) {
                        break;
                    }
                    [$count] = Strings::unpackSSH2('N', $reply);
                    for ($i = 0; $i < $count; $i++) {
                        [$name] = Strings::unpackSSH2('s', $reply);
                        if ($this->version < 4) {
                            [$longName] = Strings::unpackSSH2('s', $reply);
                        }
                        $attributes = $this::parseAttributes($this->version, $reply);
                        if (! isset($attributes['type']) && $this->version < 4) {
                            $fileType = $this::parseLongname($longName);
                            if ($fileType) {
                                $attributes['type'] = $fileType;
                            }
                        }
                        if ($name === '.' || $name === '..') {
                            continue;
                        }
                        if (! mb_check_encoding($name, 'UTF-8')) {
                            throw new RuntimeException('SFTP returned an invalid UTF-8 directory entry.');
                        }
                        if ($seen++ < $skip) {
                            continue;
                        }
                        // A single oversized name can never advance to a next
                        // page; return a clear failure rather than looping.
                        if (strlen($name) > $nameBudget) {
                            throw new RuntimeException('A directory entry exceeds the name-byte budget.');
                        }
                        if (count($items) >= $take || $namesSize + strlen($name) > $nameBudget) {
                            $hasMore = true;
                            break 2;
                        }
                        $namesSize += strlen($name);
                        $items[] = ['name' => $name, 'attributes' => $attributes];
                    }
                }
            } finally {
                $this->close_handle($handle);
            }

            return ['items' => $items, 'has_more' => $hasMore, 'read' => $seen];
        }, $sftp, SFTP::class);
        if (! $reader instanceof Closure) {
            throw new RuntimeException('SFTP directory pagination is unavailable.');
        }

        return $reader($directory, $offset, $limit, $maxNameBytes);
    }
}
