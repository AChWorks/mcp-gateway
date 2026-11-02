<?php

namespace App\Infrastructure\Connectors\SshDirect;

use App\Domain\Targets\Target;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

final class SshManagedReverseEnrollment extends Model
{
    use HasUlids;

    protected $table = 'ssh_reverse_managed_enrollments';

    protected $fillable = [
        'target_id', 'target_record_id', 'listener_port', 'tunnel_identity',
        'login_public_key', 'control_public_key', 'control_key_hash', 'token_hash', 'token_expires_at',
        'state', 'claimed_at', 'activated_at', 'revoked_at', 'publication_pending',
    ];

    protected $hidden = ['token_hash'];

    protected function casts(): array
    {
        return [
            'listener_port' => 'integer',
            'publication_pending' => 'boolean',
            'token_expires_at' => 'immutable_datetime',
            'claimed_at' => 'immutable_datetime',
            'activated_at' => 'immutable_datetime',
            'revoked_at' => 'immutable_datetime',
        ];
    }

    /** @return BelongsTo<Target, $this> */
    public function target(): BelongsTo
    {
        return $this->belongsTo(Target::class, 'target_record_id');
    }
}
