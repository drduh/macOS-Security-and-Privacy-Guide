#!/usr/bin/env bash
# Print persistent launchd jobs as JSON with signing, behavior and anomaly flags.
#
# Usage:
#   ./printPersistent.sh [--system]  # include Apple system jobs (off by default)

#set -x  # uncomment to debug
set -o errexit
set -o nounset
set -o pipefail

INCLUDE_SYSTEM=0

requireMacos() {  # exit unless on macOS with jq
  [[ "$(uname -s)" == "Darwin" ]] || {
    printf 'script requires macOS\n' >&2
    exit 1
  }
  command -v jq >/dev/null 2>&1 || {
    printf 'script requires jq\n' >&2
    exit 1
  }
}

usage() { printf 'usage: %s [--system]\n' "$(basename "$0")" ; }

progress()    { [[ ! -t 2 ]] || printf '\r\033[Kscanning %s ...' "$1" >&2 ; }
progressEnd() { [[ ! -t 2 ]] || printf '\r\033[K' >&2 ; }

plistBool() {  # true if key exists and is true
  case "$(plistRaw "$1" "$2")" in
    1|true) return 0 ;;
    *)      return 1 ;;
  esac
}

plistExists() {
  plutil -extract "$2" xml1 -o /dev/null "$1" >/dev/null 2>&1
}

plistRaw() {  # print value at plist key path, empty if absent
  local out
  out="$(plutil -extract "$2" raw -o - "$1" 2>/dev/null)" &&
    printf '%s' "$out"
}

arrayOf() {  # emit plist key as JSON string array
  local plist="$1"
  local key="$2"
  local elems=()
  local elem
  local i=0

  while elem="$(plutil -extract "$key.$i" raw -o - "$plist" 2>/dev/null)"; do
    elems+=("$elem")
    i=$((i + 1))
  done

  if [[ "${#elems[@]}" -eq 0 ]]; then
    elem="$(plistRaw "$plist" "$key")"
    [[ -n "$elem" ]] && elems+=("$elem")
  fi

  if [[ "${#elems[@]}" -gt 0 ]]; then
    printf '%s\n' "${elems[@]}" | jq -R . | jq -s .
  else
    printf '[]'
  fi
}

argsOf() {  # program and arguments as JSON array
  local args
  args="$(arrayOf "$1" ProgramArguments)"
  [[ "$args" != "[]" ]] || args="$(arrayOf "$1" Program)"
  printf '%s' "$args"
}

signingAuthority() {  # signing authority or unsigned-or-missing
  local first

  [[ -e "$1" ]] || {
    printf 'unsigned-or-missing'
    return
  }

  first="$(codesign -dv --verbose=4 "$1" 2>&1 |
    sed -n 's/^Authority=//p' |
    head -1)"

  printf '%s' "${first:-unsigned-or-missing}"
}

isWrapper() {  # true for known wrapper executables
  case "$(basename "$1")" in
    launchctl|sh|bash|zsh|dash|python*|ruby|osascript|env) return 0 ;;
    *) return 1 ;;
  esac
}

behaviorOf() {  # launchd capabilities
  local plist="$1"
  local target="$2"
  local out=""

  add() {
    out="${out:+$out,}$1"
  }

  plistBool "$plist" RunAtLoad && add run-at-load
  plistExists "$plist" KeepAlive &&
    ! { [[ "$(plistRaw "$plist" KeepAlive)" == "0" ]] ||
        [[ "$(plistRaw "$plist" KeepAlive)" == "false" ]]; } &&
    add keepalive

  if plistExists "$plist" StartCalendarInterval ||
    plistExists "$plist" StartInterval; then
    add scheduled
  fi

  plistExists "$plist" Sockets && add socket-listener
  plistExists "$plist" MachServices && add mach-services

  if plistExists "$plist" WatchPaths ||
    plistExists "$plist" QueueDirectories; then
    add watch-paths
  fi

  plistBool "$plist" StartOnMount && add start-on-mount

  case "$target" in
    "${HOME}/Library"/*) add user-library ;;
  esac

  printf '%s' "$out"
}

flagsFor() {  # anomaly flags
  local plist="$1"
  local target="$2"
  local authority="$3"
  local wrapper="$4"
  local flags=""

  add() {
    flags="${flags:+$flags,}$1"
  }

  [[ -n "$wrapper" ]] && add wrapper
  [[ "$authority" == "unsigned-or-missing" ]] && add unsigned

  case "$target" in
    /var/folders/*|/private/var/folders/*|/tmp/*|/private/tmp/*|\
    "${TMPDIR:-/nope}"*|"${HOME}/Downloads"/*)
      add temp-dir
      ;;
  esac

  if plistExists "$plist" StartCalendarInterval ||
    plistExists "$plist" StartInterval; then
    plistBool "$plist" RunAtLoad || add delayed-start
  fi

  plistBool "$plist" AbandonProcessGroup && add abandons-children

  if [[ -n "$target" ]] &&
    xattr -p com.apple.quarantine "$target" >/dev/null 2>&1; then
    add quarantined
  fi

  printf '%s' "$flags"
}

itemJson() {  # emit job as JSON
  jq -cn \
    --arg label "$1" \
    --argjson args "$2" \
    --argjson bundleIds "$3" \
    --arg signedBy "$4" \
    --arg behavior "$5" \
    --arg flags "$6" '
      {
        label: $label,
        bundle_ids: $bundleIds,
        target: ($args[0] // null),
        args: (if ($args | length) > 1 then $args else null end),
        signed_by: (if ($args | length) == 0 then null else $signedBy end),
        behavior: ($behavior | split(",") | map(select(length > 0))),
        flags: ($flags | split(",") | map(select(length > 0)))
      }
      | with_entries(select(.value != null and .value != [] and .value != ""))
    '
}

plistItem() {  # inspect plist
  local label
  local args
  local bundle_ids
  local target
  local authority
  local wrapper=""
  local behavior
  local flags

  label="$(plistRaw "$1" Label)"
  [[ -n "$label" ]] || label="$(basename "$1" .plist)"
  progress "$label"

  args="$(argsOf "$1")"
  bundle_ids="$(arrayOf "$1" AssociatedBundleIdentifiers)"
  target="$(jq -r '.[0] // empty' <<<"$args")"
  behavior="$(behaviorOf "$1" "$target")"

  if [[ -z "$target" ]]; then
    itemJson "$label" "$args" "$bundle_ids" "" "$behavior" "no-target"
    return
  fi

  authority="$(signingAuthority "$target")"

  if isWrapper "$target"; then
    wrapper=1
  fi

  flags="$(flagsFor "$1" "$target" "$authority" "$wrapper")"
  itemJson "$label" "$args" "$bundle_ids" "$authority" "$behavior" "$flags"
}

scanDir() {  # scan plists into JSON array
  local plist

  if [[ ! -d "$1" ]]; then
    jq -n '[]'
    return
  fi

  while IFS= read -r -d '' plist; do
    plistItem "$plist"
  done < <(find "$1" -maxdepth 1 -name '*.plist' -print0 2>/dev/null) |
    jq -s .
}

printDaemons() {
  DAEMONS="$(scanDir "/Library/LaunchDaemons")"
}

printAgents() {
  AGENTS="$(scanDir "/Library/LaunchAgents")"
}

printUserAgents() {
  USER_AGENTS="$(scanDir "${HOME}/Library/LaunchAgents")"
}

printSystemDaemons() {
  SYSTEM_DAEMONS="$(scanDir "/System/Library/LaunchDaemons")"
}

printSystemAgents() {
  SYSTEM_AGENTS="$(scanDir "/System/Library/LaunchAgents")"
}

printReport() {  # assemble final JSON report
  jq -n \
    --argjson daemon "$DAEMONS" \
    --argjson agent "$AGENTS" \
    --argjson user "$USER_AGENTS" \
    --argjson systemDaemon "$SYSTEM_DAEMONS" \
    --argjson systemAgent "$SYSTEM_AGENTS" \
    --argjson withSystem "$INCLUDE_SYSTEM" '
      {
        launch: (
          {
            daemon: $daemon,
            agent: $agent,
            "user-agent": $user
          }
          + if $withSystem == 1 then
              {
                "system-daemon": $systemDaemon,
                "system-agent": $systemAgent
              }
            else
              {}
            end
        )
      }
    '
}

main() {
  requireMacos

  local arg
  for arg in "$@"; do
    case "$arg" in
      --system)  INCLUDE_SYSTEM=1 ;;
      -h|--help) usage;     exit 0 ;;
      *)         usage >&2; exit 1 ;;
    esac
  done

  printDaemons
  printAgents
  printUserAgents

  if [[ "$INCLUDE_SYSTEM" -eq 1 ]]; then
    printSystemDaemons
    printSystemAgents
  else
    SYSTEM_DAEMONS='[]'
    SYSTEM_AGENTS='[]'
  fi

  progressEnd
  printReport
}

main "$@"