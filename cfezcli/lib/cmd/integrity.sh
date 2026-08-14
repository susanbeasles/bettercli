# shellcheck shell=bash
# cf integrity — inspect and manage the pin.
cmd_integrity() {
  case "${1:-show}" in
    show)
      integrity_check
      printf '\nbundle    %s\n' "$BUNDLE_ROOT"
      printf 'files     %s\n' "$BUNDLE_FILES"
      printf 'hash      '; render_hash "$BUNDLE_HASH"; printf '\n'
      printf 'state     %s\n' "$INTEGRITY_STATE"
      [ "$INTEGRITY_STATE" = MISMATCH ] && printf 'pinned    %s\n' "$PINNED"
      printf 'pinned_at %s\n' "${PINNED_AT:--}"
      printf 'hashing   every invocation (full content hash, no cache)\n'
      printf 'store     %s\n\n' "$CFDNS_INTEGRITY"
      ;;
    pin)      integrity_pin ;;
    verify)   integrity_verify ;;
    diff)     integrity_diff ;;
    manifest) integrity_check; printf '%s\n' "$BUNDLE_MANIFEST" ;;
    *) die "cf integrity show|pin|verify|diff|manifest" ;;
  esac
}
