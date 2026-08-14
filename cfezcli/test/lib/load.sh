# shellcheck shell=bash
# Load the tool's modules the way `cf` does: from lib/cli/modules.txt.
#
# Tests used to source a hand-picked list, which went stale silently whenever a
# module was extracted — the backoff test failed with "with_retry: command not found"
# the moment retry logic moved into its own file. Reading the same manifest the
# entrypoint reads means a test cannot drift from the program.
load_modules() {
  local root="${1:-$PWD}" upto="${2:-}"
  CFDNS_LIB="$root/lib"
  local mod
  while IFS= read -r mod; do
    case "$mod" in ''|\#*) continue ;; esac
    # shellcheck source=/dev/null
    . "$CFDNS_LIB/$mod"
    if [ -n "$upto" ] && [ "$mod" = "$upto" ]; then break; fi
  done < "$CFDNS_LIB/cli/modules.txt"
  return 0
}
