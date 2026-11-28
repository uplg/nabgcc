#!/usr/bin/env bash
# The test runs .github/lapin-suites describes, for scripts/ci-local.sh
# and .github/workflows/emulator.yml alike:
#   r3     the nextest filter of the run on r3: every test binary but
#          those that pick their images themselves (lapin_fixed);
#   lapin  the arguments of the run on lapin: the suites that follow
#          NABEMU_FIRMWARE, then those of lapin_fixed, a --test each.
set -euo pipefail
list="$(dirname "$0")/../.github/lapin-suites"
read -ra suites < <(sed -n 's/^lapin_suites: //p' "$list")
read -ra fixed < <(sed -n 's/^lapin_fixed: //p' "$list")
case "${1:-}" in
r3)
    printf 'not (%s)\n' "$(printf 'binary(%s) | ' "${fixed[@]}" | sed 's/ | $//')"
    ;;
lapin)
    for t in "${fixed[@]}"; do suites+=(--test "$t"); done
    printf '%s\n' "${suites[*]}"
    ;;
*)
    echo "usage: $0 r3|lapin" >&2
    exit 2
    ;;
esac
