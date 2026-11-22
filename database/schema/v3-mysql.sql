CREATE TABLE `activity_events` (
  `id` char(26) NOT NULL,
  `correlation_id` char(36) NOT NULL,
  `actor_type` varchar(32) NOT NULL,
  `actor_id` varchar(128) DEFAULT NULL,
  `client_id_hash` char(64) DEFAULT NULL,
  `target_id` varchar(128) DEFAULT NULL,
  `operation` varchar(128) NOT NULL,
  `outcome` varchar(32) NOT NULL,
  `error_code` varchar(64) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `target_record_id` char(26) DEFAULT NULL,
  `connector_type_snapshot` varchar(64) DEFAULT NULL,
  `client_profile_key` varchar(48) DEFAULT NULL,
  `diagnostic_context` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`diagnostic_context`)),
  PRIMARY KEY (`id`),
  KEY `activity_events_correlation_id_index` (`correlation_id`),
  KEY `activity_events_client_id_hash_index` (`client_id_hash`),
  KEY `activity_events_operation_index` (`operation`),
  KEY `activity_events_outcome_index` (`outcome`),
  KEY `activity_events_error_code_index` (`error_code`),
  KEY `activity_events_created_at_index` (`created_at`),
  KEY `activity_events_target_id_index` (`target_id`),
  KEY `activity_events_target_record_id_index` (`target_record_id`),
  KEY `activity_events_client_profile_key_index` (`client_profile_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `activity_retention_state` (
  `id` tinyint(3) unsigned NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `arvan_api_target_configs` (
  `id` char(26) NOT NULL,
  `target_record_id` char(26) NOT NULL,
  `base_url` varchar(1024) NOT NULL,
  `spec_url` varchar(1024) DEFAULT NULL,
  `probe_path` varchar(1024) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `arvan_api_target_configs_target_record_id_unique` (`target_record_id`),
  CONSTRAINT `arvan_api_target_configs_target_record_id_foreign` FOREIGN KEY (`target_record_id`) REFERENCES `targets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `chatgpt_file_admission_guard` (
  `id` tinyint(3) unsigned NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `chatgpt_file_admission_leases` (
  `id` char(36) NOT NULL,
  `mode` varchar(16) NOT NULL,
  `reserved_bytes` bigint(20) unsigned NOT NULL,
  `expires_at` timestamp NOT NULL,
  `created_at` timestamp NOT NULL,
  PRIMARY KEY (`id`),
  KEY `chatgpt_file_leases_expiry` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `connection_relays` (
  `id` char(26) NOT NULL,
  `relay_id` varchar(64) NOT NULL,
  `display_name` varchar(160) NOT NULL,
  `control_host` varchar(253) NOT NULL,
  `control_port` smallint(5) unsigned NOT NULL,
  `control_user` varchar(128) NOT NULL,
  `control_host_key` text NOT NULL,
  `local_socks_port` smallint(5) unsigned NOT NULL,
  `configuration_revision` int(10) unsigned NOT NULL DEFAULT 1,
  `lifecycle_revision` int(10) unsigned NOT NULL DEFAULT 1,
  `enabled` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  `login_public_key` text DEFAULT NULL,
  `login_private_key_encrypted` longtext DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `connection_relays_relay_id_unique` (`relay_id`),
  UNIQUE KEY `connection_relays_local_socks_port_unique` (`local_socks_port`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `oauth_access_tokens` (
  `id` varchar(128) NOT NULL,
  `authorization_id` char(26) NOT NULL,
  `client_id` varchar(255) NOT NULL,
  `user_id` bigint(20) unsigned NOT NULL,
  `resource` varchar(1024) NOT NULL,
  `scopes` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`scopes`)),
  `expires_at` timestamp NOT NULL,
  `revoked_at` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `oauth_access_tokens_user_id_foreign` (`user_id`),
  KEY `oauth_access_tokens_authorization_id_revoked_at_index` (`authorization_id`,`revoked_at`),
  CONSTRAINT `oauth_access_tokens_authorization_id_foreign` FOREIGN KEY (`authorization_id`) REFERENCES `oauth_authorizations` (`id`) ON DELETE CASCADE,
  CONSTRAINT `oauth_access_tokens_user_id_foreign` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `oauth_auth_codes` (
  `id` varchar(128) NOT NULL,
  `authorization_id` char(26) NOT NULL,
  `client_id` varchar(255) NOT NULL,
  `user_id` bigint(20) unsigned NOT NULL,
  `resource` varchar(1024) NOT NULL,
  `scopes` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`scopes`)),
  `expires_at` timestamp NOT NULL,
  `revoked_at` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `oauth_auth_codes_user_id_foreign` (`user_id`),
  KEY `oauth_auth_codes_authorization_id_revoked_at_index` (`authorization_id`,`revoked_at`),
  CONSTRAINT `oauth_auth_codes_authorization_id_foreign` FOREIGN KEY (`authorization_id`) REFERENCES `oauth_authorizations` (`id`) ON DELETE CASCADE,
  CONSTRAINT `oauth_auth_codes_user_id_foreign` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `oauth_authorizations` (
  `id` char(26) NOT NULL,
  `user_id` bigint(20) unsigned NOT NULL,
  `client_id` varchar(255) NOT NULL,
  `resource` varchar(1024) NOT NULL,
  `resource_hash` char(64) NOT NULL,
  `scopes` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`scopes`)),
  `revoked_at` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  `client_profile_key` varchar(48) DEFAULT NULL,
  `client_profile_generation` int(10) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `oauth_authorizations_user_id_foreign` (`user_id`),
  KEY `oauth_authorizations_lookup` (`client_id`,`user_id`,`resource_hash`),
  KEY `oauth_authorizations_revoked_at_index` (`revoked_at`),
  KEY `oauth_authorizations_client_profile_key_index` (`client_profile_key`),
  CONSTRAINT `oauth_authorizations_user_id_foreign` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `oauth_client_assertions` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `client_id` varchar(255) NOT NULL,
  `jti_hash` char(64) NOT NULL,
  `expires_at` timestamp NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `oauth_client_assertions_unique` (`client_id`,`jti_hash`),
  KEY `oauth_client_assertions_expires_at_index` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `oauth_client_profiles` (
  `profile_key` varchar(48) NOT NULL,
  `client_id` varchar(255) NOT NULL,
  `auth_strategy` varchar(48) NOT NULL,
  `generation` int(10) unsigned NOT NULL DEFAULT 1,
  `disabled_at` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`profile_key`),
  UNIQUE KEY `oauth_client_profiles_client_id_unique` (`client_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `oauth_dcr_clients` (
  `client_id` varchar(64) NOT NULL,
  `profile_key` varchar(48) NOT NULL,
  `secret_hash` char(64) NOT NULL,
  `redirect_uris` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`redirect_uris`)),
  `display_name` varchar(160) NOT NULL,
  `retired_at` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  `ever_authorized_at` timestamp NULL DEFAULT NULL,
  `auto_retirement_eligible` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`client_id`),
  UNIQUE KEY `oauth_dcr_clients_profile_key_unique` (`profile_key`),
  KEY `oauth_dcr_clients_retired_at_index` (`retired_at`),
  KEY `oauth_dcr_clients_admin_history` (`created_at`,`client_id`),
  KEY `oauth_dcr_clients_reclaim` (`retired_at`,`auto_retirement_eligible`,`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `oauth_refresh_recoveries` (
  `old_token_hash` char(64) NOT NULL,
  `old_refresh_token_id` varchar(128) NOT NULL,
  `successor_access_token_id` varchar(128) NOT NULL,
  `successor_refresh_token_id` varchar(128) DEFAULT NULL,
  `authorization_id` char(26) NOT NULL,
  `client_id` varchar(255) NOT NULL,
  `user_id` bigint(20) unsigned NOT NULL,
  `resource` varchar(1024) NOT NULL,
  `effective_scopes` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`effective_scopes`)),
  `response_ciphertext` longtext NOT NULL,
  `recovery_expires_at` timestamp NOT NULL,
  `uses_remaining` tinyint(3) unsigned NOT NULL DEFAULT 1,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`old_token_hash`),
  KEY `oauth_recovery_old_refresh_fk` (`old_refresh_token_id`),
  KEY `oauth_recovery_access_fk` (`successor_access_token_id`),
  KEY `oauth_recovery_refresh_fk` (`successor_refresh_token_id`),
  KEY `oauth_recovery_user_fk` (`user_id`),
  KEY `oauth_recovery_expiry_idx` (`recovery_expires_at`),
  KEY `oauth_recovery_authorization_idx` (`authorization_id`,`created_at`),
  CONSTRAINT `oauth_recovery_access_fk` FOREIGN KEY (`successor_access_token_id`) REFERENCES `oauth_access_tokens` (`id`) ON DELETE CASCADE,
  CONSTRAINT `oauth_recovery_authorization_fk` FOREIGN KEY (`authorization_id`) REFERENCES `oauth_authorizations` (`id`) ON DELETE CASCADE,
  CONSTRAINT `oauth_recovery_old_refresh_fk` FOREIGN KEY (`old_refresh_token_id`) REFERENCES `oauth_refresh_tokens` (`id`) ON DELETE CASCADE,
  CONSTRAINT `oauth_recovery_refresh_fk` FOREIGN KEY (`successor_refresh_token_id`) REFERENCES `oauth_refresh_tokens` (`id`) ON DELETE CASCADE,
  CONSTRAINT `oauth_recovery_user_fk` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `oauth_refresh_tokens` (
  `id` varchar(128) NOT NULL,
  `access_token_id` varchar(128) NOT NULL,
  `authorization_id` char(26) NOT NULL,
  `client_id` varchar(255) NOT NULL,
  `user_id` bigint(20) unsigned NOT NULL,
  `resource` varchar(1024) NOT NULL,
  `expires_at` timestamp NOT NULL,
  `revoked_at` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `oauth_refresh_tokens_user_id_foreign` (`user_id`),
  KEY `oauth_refresh_tokens_access_token_id_foreign` (`access_token_id`),
  KEY `oauth_refresh_tokens_authorization_id_revoked_at_index` (`authorization_id`,`revoked_at`),
  CONSTRAINT `oauth_refresh_tokens_access_token_id_foreign` FOREIGN KEY (`access_token_id`) REFERENCES `oauth_access_tokens` (`id`) ON DELETE CASCADE,
  CONSTRAINT `oauth_refresh_tokens_authorization_id_foreign` FOREIGN KEY (`authorization_id`) REFERENCES `oauth_authorizations` (`id`) ON DELETE CASCADE,
  CONSTRAINT `oauth_refresh_tokens_user_id_foreign` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `operational_setting_changes` (
  `id` char(26) NOT NULL,
  `setting_key` varchar(64) NOT NULL,
  `previous_value` int(10) unsigned DEFAULT NULL,
  `new_value` int(10) unsigned DEFAULT NULL,
  `version` bigint(20) unsigned NOT NULL,
  `actor_user_id` bigint(20) unsigned DEFAULT NULL,
  `created_at` timestamp NOT NULL,
  PRIMARY KEY (`id`),
  KEY `operational_setting_changes_actor_user_id_foreign` (`actor_user_id`),
  KEY `operational_setting_changes_setting_key_created_at_index` (`setting_key`,`created_at`),
  CONSTRAINT `operational_setting_changes_actor_user_id_foreign` FOREIGN KEY (`actor_user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `operational_settings` (
  `id` tinyint(3) unsigned NOT NULL,
  `overrides` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`overrides`)),
  `version` bigint(20) unsigned NOT NULL DEFAULT 0,
  `changed_by` bigint(20) unsigned DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  `wp_connect_timeout_seconds` tinyint(3) unsigned DEFAULT NULL,
  `wp_request_timeout_seconds` tinyint(3) unsigned DEFAULT NULL,
  `ssh_transfer_max_kib` int(10) unsigned DEFAULT NULL,
  `ssh_transfer_max_seconds` smallint(5) unsigned DEFAULT NULL,
  `ssh_command_timeout_seconds` smallint(5) unsigned DEFAULT NULL,
  `ssh_command_max_kib` smallint(5) unsigned DEFAULT NULL,
  `ssh_job_max_active_per_user` smallint(5) unsigned DEFAULT NULL,
  `ssh_job_max_runtime_seconds` int(10) unsigned DEFAULT NULL,
  `ssh_job_retention_hours` smallint(5) unsigned DEFAULT NULL,
  `ssh_job_preparing_grace_seconds` smallint(5) unsigned DEFAULT NULL,
  `ssh_job_reconcile_grace_seconds` smallint(5) unsigned DEFAULT NULL,
  `ssh_job_max_script_kib` smallint(5) unsigned DEFAULT NULL,
  `ssh_command_stdout_kib` smallint(5) unsigned DEFAULT NULL,
  `ssh_command_stderr_kib` smallint(5) unsigned DEFAULT NULL,
  `ssh_job_output_window_kib` smallint(5) unsigned DEFAULT NULL,
  `ssh_file_read_window_kib` smallint(5) unsigned DEFAULT NULL,
  `ssh_file_write_window_kib` smallint(5) unsigned DEFAULT NULL,
  `ssh_file_list_name_kib` smallint(5) unsigned DEFAULT NULL,
  `wp_ability_input_kib` smallint(5) unsigned DEFAULT NULL,
  `dcr_registration_capacity` int(10) unsigned DEFAULT NULL,
  `batch_max_parallelism` smallint(5) unsigned DEFAULT NULL,
  `batch_global_active` smallint(5) unsigned DEFAULT NULL,
  `batch_user_active` smallint(5) unsigned DEFAULT NULL,
  `batch_worker_max_children` smallint(5) unsigned DEFAULT NULL,
  `batch_worker_max_seconds` int(10) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `operational_settings_changed_by_foreign` (`changed_by`),
  CONSTRAINT `operational_settings_changed_by_foreign` FOREIGN KEY (`changed_by`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `password_reset_tokens` (
  `email` varchar(255) NOT NULL,
  `token` varchar(255) NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `ssh_command_jobs` (
  `id` char(26) NOT NULL,
  `target_record_id` char(26) DEFAULT NULL,
  `user_id` bigint(20) unsigned DEFAULT NULL,
  `client_identity_hash` char(64) NOT NULL,
  `request_id` char(36) NOT NULL,
  `script_digest` char(64) NOT NULL,
  `target_binding_hash` char(64) NOT NULL,
  `unit_mode` varchar(8) DEFAULT NULL,
  `status` varchar(32) NOT NULL,
  `runtime_seconds` int(10) unsigned NOT NULL,
  `exit_code` tinyint(3) unsigned DEFAULT NULL,
  `terminal_reason` varchar(32) DEFAULT NULL,
  `expires_at` timestamp NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  `admission_expires_at` timestamp NULL DEFAULT NULL,
  `operator_attested_at` timestamp NULL DEFAULT NULL,
  `operator_attested_reason` varchar(240) DEFAULT NULL,
  `operator_attested_uid` int(10) unsigned DEFAULT NULL,
  `original_user_id` bigint(20) unsigned DEFAULT NULL,
  `original_target_record_id` char(26) DEFAULT NULL,
  `original_target_id` varchar(64) DEFAULT NULL,
  `original_host` varchar(253) DEFAULT NULL,
  `original_port` smallint(5) unsigned DEFAULT NULL,
  `original_os_username` varchar(128) DEFAULT NULL,
  `original_auth_method` varchar(32) DEFAULT NULL,
  `original_host_key_digest` char(64) DEFAULT NULL,
  `preparing_expires_at` timestamp NULL DEFAULT NULL,
  `reconcile_grace_seconds` smallint(5) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ssh_jobs_one_launch_per_intent` (`target_record_id`,`user_id`,`client_identity_hash`,`request_id`),
  KEY `ssh_jobs_retention` (`status`,`expires_at`),
  KEY `ssh_jobs_active_lease` (`user_id`,`status`,`admission_expires_at`),
  KEY `ssh_jobs_client_discovery` (`user_id`,`target_record_id`,`client_identity_hash`,`target_binding_hash`,`id`),
  CONSTRAINT `ssh_command_jobs_target_record_id_foreign` FOREIGN KEY (`target_record_id`) REFERENCES `targets` (`id`) ON DELETE SET NULL,
  CONSTRAINT `ssh_command_jobs_user_id_foreign` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `ssh_direct_target_configs` (
  `id` char(26) NOT NULL,
  `target_record_id` char(26) NOT NULL,
  `host` varchar(253) NOT NULL,
  `port` smallint(5) unsigned NOT NULL,
  `username` varchar(128) NOT NULL,
  `auth_method` varchar(32) NOT NULL,
  `pinned_host_key` text NOT NULL,
  `verification_attempt_id` char(26) DEFAULT NULL,
  `observed_peer_ip` varchar(45) DEFAULT NULL,
  `observed_at` timestamp(6) NULL DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  `route_mode` varchar(16) NOT NULL DEFAULT 'direct',
  `reverse_listener_port` smallint(5) unsigned DEFAULT NULL,
  `reverse_tunnel_identity` varchar(80) DEFAULT NULL,
  `binding_revision` int(10) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ssh_direct_target_configs_target_record_id_unique` (`target_record_id`),
  UNIQUE KEY `ssh_reverse_unique_port` (`reverse_listener_port`),
  KEY `ssh_configs_host_port_idx` (`host`,`port`),
  KEY `ssh_configs_observed_ip_idx` (`observed_peer_ip`),
  CONSTRAINT `ssh_direct_target_configs_target_record_id_foreign` FOREIGN KEY (`target_record_id`) REFERENCES `targets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `ssh_job_maintenance_progress` (
  `operation` varchar(24) NOT NULL,
  `last_expires_at` timestamp NULL DEFAULT NULL,
  `last_id` char(26) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`operation`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `ssh_reverse_gateway_settings` (
  `id` tinyint(3) unsigned NOT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT 0,
  `publication_pending` tinyint(1) NOT NULL DEFAULT 0,
  `control_host` varchar(253) NOT NULL,
  `control_port` smallint(5) unsigned NOT NULL,
  `control_user` varchar(64) NOT NULL,
  `control_host_key` varchar(4096) NOT NULL,
  `revision` bigint(20) unsigned NOT NULL DEFAULT 0,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `ssh_reverse_managed_enrollments` (
  `id` char(26) NOT NULL,
  `target_id` varchar(64) NOT NULL,
  `target_record_id` char(26) NOT NULL,
  `listener_port` smallint(5) unsigned NOT NULL,
  `tunnel_identity` varchar(80) NOT NULL,
  `control_public_key` text DEFAULT NULL,
  `control_key_hash` char(64) DEFAULT NULL,
  `login_public_key` text NOT NULL,
  `token_hash` char(64) DEFAULT NULL,
  `token_expires_at` timestamp NULL DEFAULT NULL,
  `claimed_at` timestamp NULL DEFAULT NULL,
  `activated_at` timestamp NULL DEFAULT NULL,
  `revoked_at` timestamp NULL DEFAULT NULL,
  `state` varchar(16) NOT NULL DEFAULT 'pending',
  `publication_pending` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ssh_reverse_managed_enrollments_target_id_unique` (`target_id`),
  UNIQUE KEY `ssh_reverse_managed_enrollments_target_record_id_unique` (`target_record_id`),
  UNIQUE KEY `ssh_reverse_managed_enrollments_listener_port_unique` (`listener_port`),
  UNIQUE KEY `ssh_reverse_managed_enrollments_tunnel_identity_unique` (`tunnel_identity`),
  UNIQUE KEY `ssh_reverse_managed_enrollments_control_key_hash_unique` (`control_key_hash`),
  CONSTRAINT `ssh_reverse_managed_enrollments_target_record_id_foreign` FOREIGN KEY (`target_record_id`) REFERENCES `targets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `ssh_reverse_managed_retired_ports` (
  `listener_port` smallint(5) unsigned NOT NULL,
  `target_id` varchar(64) NOT NULL,
  `retired_at` timestamp NOT NULL,
  PRIMARY KEY (`listener_port`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `target_check_operation_targets` (
  `id` char(26) NOT NULL,
  `operation_id` char(36) NOT NULL,
  `target_record_id` char(26) DEFAULT NULL,
  `position` tinyint(3) unsigned NOT NULL,
  `target_id_snapshot` varchar(64) NOT NULL,
  `display_name_snapshot` varchar(160) NOT NULL,
  `status` varchar(32) NOT NULL,
  `attempts` tinyint(3) unsigned NOT NULL DEFAULT 0,
  `attempt_token` char(36) DEFAULT NULL,
  `error_code` varchar(64) DEFAULT NULL,
  `started_at` timestamp(6) NULL DEFAULT NULL,
  `finished_at` timestamp(6) NULL DEFAULT NULL,
  `created_at` timestamp(6) NULL DEFAULT NULL,
  `updated_at` timestamp(6) NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `target_check_position_unique` (`operation_id`,`position`),
  UNIQUE KEY `target_check_snapshot_unique` (`operation_id`,`target_id_snapshot`),
  KEY `target_check_operation_targets_target_record_id_foreign` (`target_record_id`),
  KEY `target_check_claim_idx` (`operation_id`,`status`,`position`),
  CONSTRAINT `target_check_operation_targets_operation_id_foreign` FOREIGN KEY (`operation_id`) REFERENCES `target_check_operations` (`id`) ON DELETE CASCADE,
  CONSTRAINT `target_check_operation_targets_target_record_id_foreign` FOREIGN KEY (`target_record_id`) REFERENCES `targets` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `target_check_operations` (
  `id` char(36) NOT NULL,
  `creator_user_id` bigint(20) unsigned NOT NULL,
  `idempotency_key` char(36) NOT NULL,
  `active_slot` tinyint(3) unsigned DEFAULT NULL,
  `status` varchar(32) NOT NULL,
  `started_at` timestamp(6) NULL DEFAULT NULL,
  `completed_at` timestamp(6) NULL DEFAULT NULL,
  `created_at` timestamp(6) NULL DEFAULT NULL,
  `updated_at` timestamp(6) NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `target_check_creator_idempotency_unique` (`creator_user_id`,`idempotency_key`),
  UNIQUE KEY `target_check_creator_active_unique` (`creator_user_id`,`active_slot`),
  KEY `target_check_completed_idx` (`completed_at`,`id`),
  CONSTRAINT `target_check_operations_creator_user_id_foreign` FOREIGN KEY (`creator_user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `target_credentials` (
  `id` char(26) NOT NULL,
  `target_record_id` char(26) NOT NULL,
  `connector_type` varchar(64) NOT NULL,
  `purpose` varchar(96) NOT NULL,
  `encrypted_payload` longtext NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `target_credential_purpose_unique` (`target_record_id`,`connector_type`,`purpose`),
  CONSTRAINT `target_credentials_target_record_id_foreign` FOREIGN KEY (`target_record_id`) REFERENCES `targets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `target_group_permission_denials` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `target_group_id` char(26) NOT NULL,
  `permission` varchar(96) NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `target_group_denials_unique` (`target_group_id`,`permission`),
  KEY `target_group_permission_denials_permission_target_group_id_index` (`permission`,`target_group_id`),
  CONSTRAINT `target_group_permission_denials_target_group_id_foreign` FOREIGN KEY (`target_group_id`) REFERENCES `target_groups` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `target_group_targets` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `target_group_id` char(26) NOT NULL,
  `target_record_id` char(26) NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `target_group_target_unique` (`target_group_id`,`target_record_id`),
  KEY `target_group_target_idx` (`target_record_id`,`target_group_id`),
  CONSTRAINT `target_group_targets_target_group_id_foreign` FOREIGN KEY (`target_group_id`) REFERENCES `target_groups` (`id`) ON DELETE CASCADE,
  CONSTRAINT `target_group_targets_target_record_id_foreign` FOREIGN KEY (`target_record_id`) REFERENCES `targets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `target_group_users` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `target_group_id` char(26) NOT NULL,
  `user_id` bigint(20) unsigned NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `target_group_users_target_group_id_user_id_unique` (`target_group_id`,`user_id`),
  KEY `target_group_users_user_id_target_group_id_index` (`user_id`,`target_group_id`),
  CONSTRAINT `target_group_users_target_group_id_foreign` FOREIGN KEY (`target_group_id`) REFERENCES `target_groups` (`id`) ON DELETE CASCADE,
  CONSTRAINT `target_group_users_user_id_foreign` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `target_groups` (
  `id` char(26) NOT NULL,
  `name` varchar(160) NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `target_groups_name_unique` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `targets` (
  `id` char(26) NOT NULL,
  `target_id` varchar(64) NOT NULL,
  `display_name` varchar(160) NOT NULL,
  `connector_type` varchar(64) NOT NULL,
  `connection_state` varchar(32) NOT NULL DEFAULT 'disconnected',
  `last_error_code` varchar(64) DEFAULT NULL,
  `last_tested_at` timestamp(6) NULL DEFAULT NULL,
  `connected_at` timestamp NULL DEFAULT NULL,
  `last_success_at` timestamp(6) NULL DEFAULT NULL,
  `last_failure_at` timestamp(6) NULL DEFAULT NULL,
  `last_failure_code` varchar(64) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  `operations_paused` tinyint(1) NOT NULL DEFAULT 0,
  `ai_guidance` text DEFAULT NULL,
  `relay_record_id` char(26) DEFAULT NULL,
  `relay_binding_revision` int(10) unsigned NOT NULL DEFAULT 0,
  `created_by_user_id` bigint(20) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `targets_target_id_unique` (`target_id`),
  KEY `targets_type_state_idx` (`connector_type`,`connection_state`),
  KEY `targets_name_id_idx` (`display_name`,`target_id`),
  KEY `targets_state_name_idx` (`connection_state`,`display_name`,`target_id`),
  KEY `targets_state_success_idx` (`connection_state`,`last_success_at`),
  KEY `targets_relay_record_id_foreign` (`relay_record_id`),
  KEY `targets_created_by_user_id_foreign` (`created_by_user_id`),
  CONSTRAINT `targets_created_by_user_id_foreign` FOREIGN KEY (`created_by_user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `targets_relay_record_id_foreign` FOREIGN KEY (`relay_record_id`) REFERENCES `connection_relays` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `user_permission_denials` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` bigint(20) unsigned NOT NULL,
  `permission` varchar(96) NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_permission_denials_user_id_permission_unique` (`user_id`,`permission`),
  CONSTRAINT `user_permission_denials_user_id_foreign` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `user_target_access` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` bigint(20) unsigned NOT NULL,
  `target_record_id` char(26) NOT NULL,
  `allowed` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_target_access_user_id_target_record_id_unique` (`user_id`,`target_record_id`),
  KEY `user_target_access_target_record_id_foreign` (`target_record_id`),
  KEY `user_target_access_user_id_allowed_index` (`user_id`,`allowed`),
  CONSTRAINT `user_target_access_target_record_id_foreign` FOREIGN KEY (`target_record_id`) REFERENCES `targets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `user_target_access_user_id_foreign` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `user_target_permission_denials` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` bigint(20) unsigned NOT NULL,
  `target_record_id` char(26) NOT NULL,
  `permission` varchar(96) NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `target_access_denials_unique` (`user_id`,`target_record_id`,`permission`),
  KEY `user_target_permission_denials_target_record_id_foreign` (`target_record_id`),
  KEY `target_user_permission_idx` (`user_id`,`permission`),
  CONSTRAINT `user_target_permission_denials_target_record_id_foreign` FOREIGN KEY (`target_record_id`) REFERENCES `targets` (`id`) ON DELETE CASCADE,
  CONSTRAINT `user_target_permission_denials_user_id_foreign` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `users` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `email_verified_at` timestamp NULL DEFAULT NULL,
  `password` varchar(255) NOT NULL,
  `remember_token` varchar(100) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  `role` varchar(32) NOT NULL DEFAULT 'viewer',
  `target_scope_mode` varchar(16) NOT NULL DEFAULT 'selected',
  `access_enabled` tinyint(1) NOT NULL DEFAULT 1,
  `ai_access_enabled` tinyint(1) NOT NULL DEFAULT 0,
  `self_created_target_access` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `users_email_unique` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `wordpress_publish_group_grants` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` bigint(20) unsigned NOT NULL,
  `target_group_id` char(26) NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `wp_publish_group_grant_unique` (`user_id`,`target_group_id`),
  KEY `wordpress_publish_group_grants_target_group_id_foreign` (`target_group_id`),
  CONSTRAINT `wordpress_publish_group_grants_target_group_id_foreign` FOREIGN KEY (`target_group_id`) REFERENCES `target_groups` (`id`) ON DELETE CASCADE,
  CONSTRAINT `wordpress_publish_group_grants_user_id_foreign` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `wp_ai_bridge_credential_metadata` (
  `credential_id` char(26) NOT NULL,
  `client_id` varchar(255) NOT NULL,
  `resource_url` varchar(1024) NOT NULL,
  `binding_hash` char(64) NOT NULL,
  `access_expires_at` timestamp NULL DEFAULT NULL,
  `refresh_expires_at` timestamp NULL DEFAULT NULL,
  `refresh_due_at` timestamp NULL DEFAULT NULL,
  `generation` bigint(20) unsigned NOT NULL DEFAULT 1,
  PRIMARY KEY (`credential_id`),
  KEY `wp_credential_client_binding_idx` (`client_id`,`binding_hash`),
  KEY `wp_credential_refresh_due_idx` (`refresh_due_at`),
  CONSTRAINT `wp_ai_bridge_credential_metadata_credential_id_foreign` FOREIGN KEY (`credential_id`) REFERENCES `target_credentials` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `wp_ai_bridge_oauth_flows` (
  `id` char(26) NOT NULL,
  `target_record_id` char(26) NOT NULL,
  `state_hash` char(64) NOT NULL,
  `encrypted_context` longtext NOT NULL,
  `expires_at` timestamp NOT NULL,
  `consumed_at` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `wp_ai_bridge_oauth_flows_target_record_id_unique` (`target_record_id`),
  UNIQUE KEY `wp_ai_bridge_oauth_flows_state_hash_unique` (`state_hash`),
  KEY `wp_ai_bridge_oauth_flows_expires_at_index` (`expires_at`),
  CONSTRAINT `wp_ai_bridge_oauth_flows_target_record_id_foreign` FOREIGN KEY (`target_record_id`) REFERENCES `targets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `wp_ai_bridge_refresh_intents` (
  `id` char(26) NOT NULL,
  `target_record_id` char(26) NOT NULL,
  `credential_id` char(26) NOT NULL,
  `generation` bigint(20) unsigned NOT NULL,
  `attempts` tinyint(3) unsigned NOT NULL DEFAULT 1,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  `request_timeout_seconds` smallint(5) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `wp_ai_bridge_refresh_intents_target_record_id_unique` (`target_record_id`),
  KEY `wp_ai_bridge_refresh_intents_credential_id_foreign` (`credential_id`),
  CONSTRAINT `wp_ai_bridge_refresh_intents_credential_id_foreign` FOREIGN KEY (`credential_id`) REFERENCES `target_credentials` (`id`) ON DELETE CASCADE,
  CONSTRAINT `wp_ai_bridge_refresh_intents_target_record_id_foreign` FOREIGN KEY (`target_record_id`) REFERENCES `targets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `wp_ai_bridge_revocation_intents` (
  `id` char(26) NOT NULL,
  `target_record_id` char(26) NOT NULL,
  `kind` varchar(16) NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  `phase` varchar(24) NOT NULL DEFAULT 'legacy_unknown',
  `credential_id` char(26) DEFAULT NULL,
  `generation` bigint(20) unsigned DEFAULT NULL,
  `token_total` tinyint(3) unsigned DEFAULT NULL,
  `token_confirmed` tinyint(3) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `wp_ai_bridge_revocation_intents_target_record_id_unique` (`target_record_id`),
  KEY `wp_ai_bridge_revocation_intents_kind_index` (`kind`),
  CONSTRAINT `wp_ai_bridge_revocation_intents_target_record_id_foreign` FOREIGN KEY (`target_record_id`) REFERENCES `targets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `wp_ai_bridge_target_configs` (
  `id` char(26) NOT NULL,
  `target_record_id` char(26) NOT NULL,
  `base_url` varchar(1024) NOT NULL,
  `base_url_hash` char(64) NOT NULL,
  `mcp_resource_url` varchar(1024) NOT NULL,
  `oauth_issuer_url` varchar(1024) NOT NULL,
  `oauth_authorization_url` varchar(1024) NOT NULL,
  `oauth_token_url` varchar(1024) NOT NULL,
  `oauth_revocation_url` varchar(1024) NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  `metadata_checked_at` timestamp(6) NULL DEFAULT NULL,
  `metadata_reachable` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `wp_ai_bridge_target_configs_target_record_id_unique` (`target_record_id`),
  UNIQUE KEY `wp_ai_bridge_target_configs_base_url_hash_unique` (`base_url_hash`),
  CONSTRAINT `wp_ai_bridge_target_configs_target_record_id_foreign` FOREIGN KEY (`target_record_id`) REFERENCES `targets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `wp_ai_bridge_target_reservations` (
  `target_hash` char(64) NOT NULL,
  `target_url` varchar(1024) NOT NULL,
  `owner_target_id` varchar(64) NOT NULL,
  `target_record_id` char(26) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`target_hash`),
  UNIQUE KEY `wp_ai_bridge_target_reservations_target_record_id_unique` (`target_record_id`),
  KEY `wp_ai_bridge_target_reservations_owner_target_id_index` (`owner_target_id`),
  CONSTRAINT `wp_ai_bridge_target_reservations_target_record_id_foreign` FOREIGN KEY (`target_record_id`) REFERENCES `targets` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `wp_credential_maintenance_progress` (
  `id` tinyint(3) unsigned NOT NULL,
  `last_due_at` timestamp NULL DEFAULT NULL,
  `last_target_id` char(26) DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
