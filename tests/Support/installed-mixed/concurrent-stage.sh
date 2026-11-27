#!/usr/bin/env bash
# Sourced only inside run.sh's private PID/network namespace, with real
# Direct/Relay SSH and WordPress OAuth already registered and verified.
run_installed_concurrent() {
  [[ "$(id -u)" == 0 && "$(basename "$ROOT")" == mcp-gateway-installed-112-* &&
      "$MIXED_SSH_USER" =~ ^mcpac[0-9]+$ ]] || return 2
  local evidence="$ROOT/secrets/concurrent" remote="/home/$MIXED_SSH_USER/mixed-concurrent"
  install -d -o "$WORKER" -g "$WORKER_GROUP" -m 0700 "$evidence"
  runuser -u "$MIXED_SSH_USER" -- mkdir -m 0700 "$remote"
  runuser -u "$MIXED_SSH_USER" -- dd if=/dev/urandom of="$remote/payload" bs=524288 count=1 status=none
  local payload_sha
  payload_sha="$(sha256sum "$remote/payload" | cut -d" " -f1)"
  local -a sdk_concurrent=(runuser -u "$WORKER" -- env MIXED_ROOT="$ROOT" MIXED_SSH_USER="$MIXED_SSH_USER" MIXED_EXPECTED_SFTP_SHA="$payload_sha"
    php "$ROOT/client/concurrent-client.php")
  local -a sql_concurrent=(mariadb --no-defaults -uroot --socket="$ROOT/db.sock" gateway --batch --skip-column-names)
  local -a worker_concurrent=(runuser -u "$WORKER" -- php -d "curl.cainfo=$ROOT/secrets/tls.crt"
    -d "openssl.cafile=$ROOT/secrets/tls.crt" "$ROOT/gateway/artisan" gateway:batch-work --once)
  concurrent_id() {
    python3 - "$1" <<'PY'
import json, re, sys
value = json.load(open(sys.argv[1]))["batch_id"]
assert re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{26}", value), "Expected exact ULID"
print(value)
PY
  }
  concurrent_db_sample() {
    "${sql_concurrent[@]}" -e "SHOW GLOBAL STATUS WHERE Variable_name IN
      ('Threads_connected','Threads_running','Max_used_connections','Connections','Questions',
       'Innodb_row_lock_waits','Innodb_row_lock_time','Innodb_deadlocks','Aborted_connects',
       'Memory_used','Max_memory_used')" >"$evidence/$1.tsv"
  }
  concurrent_count_markers() {
    find "$remote" -maxdepth 1 -type f -name "$1" | wc -l
  }
  concurrent_wait_markers() {
    local pattern="$1" expected="$2"
    for _ in {1..100}; do
      [[ "$(concurrent_count_markers "$pattern")" -eq "$expected" ]] && return 0
      sleep 0.1
    done
    echo "Expected $expected actual remote marker(s) for $pattern" >&2
    return 1
  }
  echo 'Stage: concurrent installed MCP clients and real Batch children'
  concurrent_db_sample db-before
  python3 "$ROOT/gateway/tests/Support/installed-mixed/concurrent-sample.py"  \
    "$evidence/sample-stop" >"$evidence/processes.json" &
  local sampler=$!
  local started_ns="$(date +%s%N)"
  "${sdk_concurrent[@]}" queue >"$evidence/queue.json"
  local batch_id
  batch_id="$(concurrent_id "$evidence/queue.json")"
  # Each worker is an independent process sharing the actual installed DB,
  # cache admission and native OpenSSH connection. Marker creation is a
  # remote effect; both markers must exist before releasing either child.
  "${worker_concurrent[@]}" >"$evidence/worker-1.log" 2>&1 &
  local worker1=$!
  "${worker_concurrent[@]}" >"$evidence/worker-2.log" 2>&1 &
  local worker2=$!
  concurrent_wait_markers 'active.*' 2
  [[ "$("${sql_concurrent[@]}" -e "SELECT COUNT(*) FROM target_batch_items WHERE batch_id='$batch_id' AND status='dispatching' AND effect_admitted=1")" == 2 ]]
  echo "Both SSH children admitted; checking mixed operations and cross-client isolation"
  concurrent_db_sample db-overlap
  # Calls arrive through three independently authenticated MCP principals:
  # original Owner/acceptance, same Owner/capacity, and scoped operator.
  # The busy SSH command must not execute; SFTP is separately admitted even
  # while the relay Target's command is active. WP is real HTTPS/OAuth.
  "${sdk_concurrent[@]}" busy >"$evidence/busy.json" &
  local busy_pid=$!
  "${sdk_concurrent[@]}" wp >"$evidence/wp.json" &
  local wp_pid=$!
  "${sdk_concurrent[@]}" sftp >"$evidence/sftp.json" &
  local file_pid=$!
  wait "$busy_pid"; wait "$wp_pid"; wait "$file_pid"
  # All completed while both remote commands were still held by the barrier.
  [[ "$("${sql_concurrent[@]}" -e "SELECT COUNT(*) FROM target_batch_items WHERE batch_id='$batch_id' AND status='dispatching' AND effect_admitted=1")" == 2 ]]
  [[ ! -e "$remote/unexpected-busy" ]]
  "${sdk_concurrent[@]}" wp-denied >"$evidence/wp-denied.json"
  "${sdk_concurrent[@]}" foreign "$batch_id" >"$evidence/foreign.json"
  "${sdk_concurrent[@]}" cancel-queue >"$evidence/cancel-queue.json"
  local cancel_id
  cancel_id="$(concurrent_id "$evidence/cancel-queue.json")"
  "${sdk_concurrent[@]}" cancel "$cancel_id" >"$evidence/cancel.json"
  # Distinct client identity does not enlarge the original Owner's user
  # budget. This queued WP child has a FREE Target, unlike the busy SSH.
  "${sdk_concurrent[@]}" capacity-wp-queue >"$evidence/capacity-wp-queue.json"
  local capacity_wp_id
  capacity_wp_id="$(concurrent_id "$evidence/capacity-wp-queue.json")"
  "${worker_concurrent[@]}" >"$evidence/user-pressure-worker.log" 2>&1
  [[ "$("${sql_concurrent[@]}" -e "SELECT COUNT(*) FROM target_batch_items WHERE batch_id='$capacity_wp_id' AND status='queued' AND dispatch_attempt_id IS NULL")" == 1 ]]
  "${sdk_concurrent[@]}" wp-queue >"$evidence/wp-queue.json"
  local wp_id
  wp_id="$(concurrent_id "$evidence/wp-queue.json")"
  "${worker_concurrent[@]}" >"$evidence/wp-worker.log" 2>&1
  "${sdk_concurrent[@]}" wp-status "$wp_id" >"$evidence/wp-status.json"
  [[ "$("${sql_concurrent[@]}" -e "SELECT COUNT(*) FROM target_batch_items WHERE batch_id='$capacity_wp_id' AND status='queued' AND dispatch_attempt_id IS NULL")" == 1 ]]
  "${sdk_concurrent[@]}" capacity-wp-cancel "$capacity_wp_id" >"$evidence/capacity-wp-cancel.json"
  [[ "$("${sql_concurrent[@]}" -e "SELECT COUNT(*) FROM target_batch_items WHERE batch_id='$batch_id' AND status='dispatching' AND effect_admitted=1")" == 2 ]]
  echo "Mixed operations completed during barrier; releasing both SSH children"
  runuser -u "$MIXED_SSH_USER" -- touch "$remote/release"
  wait "$worker1"; wait "$worker2"
  "${sdk_concurrent[@]}" status "$batch_id" >"$evidence/status.json"
  "${sdk_concurrent[@]}" recovered >"$evidence/recovered.json"
  "${worker_concurrent[@]}" >"$evidence/idle-worker.log" 2>&1
  "${sdk_concurrent[@]}" cancel-status "$cancel_id" >"$evidence/cancel-status.json"
  [[ "$("${sql_concurrent[@]}" -e "SELECT COUNT(*) FROM target_batch_items WHERE batch_id='$cancel_id' AND dispatch_attempt_id IS NOT NULL")" == 0 ]]
  [[ "$(concurrent_count_markers 'active.*')" == 2 && ! -e "$remote/unexpected-cancel" ]]
  local completed_ns="$(date +%s%N)"
  concurrent_db_sample db-after
  touch "$evidence/sample-stop"
  wait "$sampler"

  # A separate real dispatch is interrupted after the native command proves
  # its effect. No deliberate wait for the production lease timeout: expire
  # only this owned row to model elapsed lease time, and restart the worker.
  # The native cache lease may legitimately survive the killed process.
  echo "Stage: admitted native effect, worker interruption and no replay"
  "${sdk_concurrent[@]}" interrupt-queue >"$evidence/interrupt-queue.json"
  local interrupt_id
  interrupt_id="$(concurrent_id "$evidence/interrupt-queue.json")"
  runuser -u "$WORKER" -- bash -c 'echo $$ >"$1"; exec php "$2" gateway:batch-work --once' \
    bash "$evidence/worker.pid" "$ROOT/gateway/artisan" >"$evidence/interrupt-worker.log" 2>&1 &
  local interrupt_wrapper=$!
  concurrent_wait_markers 'interrupted.*' 1
  [[ "$("${sql_concurrent[@]}" -e "SELECT COUNT(*) FROM target_batch_items WHERE batch_id='$interrupt_id' AND status='dispatching' AND effect_admitted=1")" == 1 ]]
  local interrupted_pid="$(cat "$evidence/worker.pid")"
  [[ "$interrupted_pid" =~ ^[0-9]+$ && "$interrupted_pid" -gt 1 ]]
  [[ "$(ps -o ppid= -p "$interrupted_pid" | tr -d ' ')" == "$interrupt_wrapper" ]]
  [[ "$(ps -o comm= -p "$interrupted_pid" | tr -d ' ')" == php ]]
  kill -KILL "$interrupted_pid"
  if wait "$interrupt_wrapper"; then
    echo 'Interrupted worker unexpectedly completed normally.' >&2; return 1
  fi
  [[ "$("${sql_concurrent[@]}" -e "UPDATE target_batch_items SET lease_expires_at=NOW()-INTERVAL 1 SECOND WHERE batch_id='$interrupt_id' AND status='dispatching' AND effect_admitted=1; SELECT ROW_COUNT()")" == 1 ]]
  "${worker_concurrent[@]}" >"$evidence/restart-worker.log" 2>&1
  "${sdk_concurrent[@]}" interrupt-status "$interrupt_id" >"$evidence/interrupt-status.json"
  "${worker_concurrent[@]}" >"$evidence/no-replay-worker.log" 2>&1
  [[ "$(concurrent_count_markers 'interrupted.*')" == 1 ]]
  [[ "$("${sql_concurrent[@]}" -e "SELECT COUNT(*) FROM target_batch_items WHERE status IN ('queued','dispatching','cancel_requested')")" == 0 ]]
  [[ "$("${sql_concurrent[@]}" -e "SELECT COUNT(*) FROM target_batch_items WHERE batch_id='$interrupt_id' AND status='outcome_unknown' AND effect_admitted=1 AND dispatch_attempt_id IS NOT NULL")" == 1 ]]
  # Only remove exact files in the fixture-owned account; any remaining
  # remote descendant is bounded by the command and enclosing PID namespace.
  runuser -u "$MIXED_SSH_USER" -- rm -rf -- "$remote"
  [[ ! -e "$remote" ]]
  python3 - "$evidence" "$started_ns" "$completed_ns" >"$MIXED_EVIDENCE/concurrent.json" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
names = ["queue", "busy", "wp", "wp-denied", "sftp", "foreign", "cancel", "wp-status",
         "status", "recovered", "cancel-status", "capacity-wp-cancel", "interrupt-status", "processes"]
data = {name: json.loads((p / (name + ".json")).read_text()) for name in names}
data["db_status_samples"] = {
    name: {k: None if v == "NULL" else int(v) for k, v in (line.split("\t") for line in
           (p / (name + ".tsv")).read_text().splitlines())}
    for name in ("db-before", "db-overlap", "db-after")
}
data.update({
    "normal_scenario_wall_ms": (int(sys.argv[3]) - int(sys.argv[2])) / 1e6,
    "simultaneous_admitted_ssh_batch_children": 2,
    "wp_and_sftp_completed_during_ssh_barrier": True,
    "same_user_budget_held_across_distinct_clients": True,
    "other_authorized_user_progressed_during_user_pressure": True,
    "physical_topology": "one disposable runner, distinct registered Direct/Relay targets and real WP, same SSH OS account",
    "queued_cancel_no_dispatch": True, "interrupted_worker_killed": True,
    "interrupted_lease_expiry": "exact admitted DB row aged by fixture after worker kill; not elapsed production TTL",
    "interrupted_remote_marker_count_after_restart": 1,
    "remaining_pending_batch_children": 0, "remote_fixture_files_removed": True,
    "killed_command_cache_lease": "finite crash-recovery lease may remain until expiry; isolated fixture discarded",
})
print(json.dumps(data, indent=2))
PY
}
