<?php

namespace App\Infrastructure\OAuth;

use RuntimeException;

/**
 * The OAuth client's durable registration changed while the user was
 * reviewing consent. This is an invalid-client decision, not a server fault.
 */
final class OAuthClientApprovalUnavailable extends RuntimeException {}
