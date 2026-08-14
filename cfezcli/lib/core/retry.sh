# shellcheck shell=bash
# Retry with exponential backoff and jitter. Knows nothing about HTTP, Cloudflare, or
# what it is retrying.
#
# The attempt communicates through a scratch directory, not through variables. An
# earlier version had the attempt set HTTP_STATUS and RETRY_AFTER in the caller's
# shell, which meant with_retry could never be called inside `$( )` — and it was,
# so the status was silently empty and nothing ever retried. Files cross a subshell
# boundary; variables do not.
#
# Scratch layout, all optional except body:
#   $scratch/body          the attempt's output
#   $scratch/status        a status token the decision function can read
#   $scratch/retry_after   seconds the server asked us to wait

RETRY_MAX="${CFDNS_MAX_RETRY:-6}"
RETRY_CAP="${CFDNS_BACKOFF_CAP:-32}"

# backoff_seconds <attempt> [retry_after] -> seconds to wait.
# A server-supplied Retry-After always wins; otherwise 2^(n-1), capped.
backoff_seconds() {
  local attempt="$1" retry_after="${2:-}"
  if [ -n "$retry_after" ] && [ "$retry_after" -eq "$retry_after" ] 2>/dev/null; then
    printf '%s' "$retry_after"
    return 0
  fi
  local wait=$(( 2 ** (attempt - 1) ))
  [ "$wait" -gt "$RETRY_CAP" ] && wait="$RETRY_CAP"
  printf '%s' "$wait"
}

# 0..999 ms. Keeps parallel invocations off the same retry schedule.
jitter_ms() { printf '%s' "$(( RANDOM % 1000 ))"; }

retry_sleep() { sleep "$(backoff_seconds "$1" "${2:-}").$(jitter_ms)"; }

retry_scratch_read() {
  local scratch="$1" name="$2"
  [ -f "$scratch/$name" ] && cat "$scratch/$name" || true
}

# with_retry <scratch> <should_retry_fn> <attempt_fn> [args...]
#
#   attempt_fn <scratch> [args...]      writes $scratch/body, returns 0 on success
#   should_retry_fn <scratch> <rc>      returns 0 to try again
#
# Returns the last attempt's exit code. The result is in $scratch/body; the caller
# owns the scratch directory and is responsible for removing it.
with_retry() {
  local scratch="$1" should_retry="$2" attempt_fn="$3"; shift 3
  local n=0 rc

  while :; do
    rm -f "$scratch/body" "$scratch/status" "$scratch/retry_after"
    "$attempt_fn" "$scratch" "$@"; rc=$?

    [ "$rc" -eq 0 ] && return 0
    "$should_retry" "$scratch" "$rc" || return "$rc"

    n=$((n + 1))
    if [ "$n" -gt "$RETRY_MAX" ]; then
      warn "giving up after $RETRY_MAX retries"
      return "$rc"
    fi

    local after status
    after="$(retry_scratch_read "$scratch" retry_after)"
    status="$(retry_scratch_read "$scratch" status)"
    warn "retry $n/$RETRY_MAX in $(backoff_seconds "$n" "$after")s${status:+ (status $status)}"
    retry_sleep "$n" "$after"
  done
}
