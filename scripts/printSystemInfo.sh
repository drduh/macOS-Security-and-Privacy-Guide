#!/usr/bin/env bash
# https://github.com/drduh/macOS-Security-and-Privacy-Guide/blob/main/scripts/printSystemInfo.sh
# Print basic system information - no sudo required.

#set -x  # uncomment to debug
set -o errexit
set -o nounset
set -o pipefail

readonly LABEL_WIDTH=15
readonly RULE_WIDTH=60

requireMacos() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    printf 'script requires macOS\n' >&2
    exit 1
  fi
}

note() { printf '(%s)' "$1"; }

row() { printf '    %-*s%s\n' "${LABEL_WIDTH}" "$1" "$2"; }

section() { printf '\n  %s\n' "$1"; }

banner() {
  local pad rule='' i
  pad=$((RULE_WIDTH - ${#1} - ${#2}))
  if ((pad < 1)); then pad=1; fi
  for ((i = 0; i < RULE_WIDTH; i++)); do rule+='─'; done
  printf '%s%*s%s\n' "$1" "${pad}" '' "$2"
  printf '%s\n' "${rule}"
}

firstLine() { "$@" 2>/dev/null | awk 'NR==1' || echo 'unavailable'; }

printSystem() {
  local boot_sec up

  boot_sec="$(sysctl -n kern.boottime | sed -E 's/^\{ sec = ([0-9]+),.*/\1/')"
  up=$(($(date +%s) - boot_sec))

  section 'System'
  row 'macOS' "$(sw_vers -productVersion) $(note "build $(sw_vers -buildVersion)")"
  row 'Kernel' "Darwin $(uname -r)"
  row 'Uptime' "$((up / 86400))d $((up % 86400 / 3600))h $((up % 3600 / 60))m"
  row 'Last Boot' "$(date -r "${boot_sec}" '+%Y-%m-%d %H:%M %Z')"
  row 'Load Avg' "$(sysctl -n vm.loadavg | tr -d '{}' | xargs)"
}

printHardware() {
  local model_name model_id chip ncpu pcores ecores cores mem_gb mem_free batt

  model_name="$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null \
    | awk -F'"' '/"product-name"/ {print $4}' || true)"
  if [[ -z "${model_name}" ]]; then
    model_name="$(system_profiler SPHardwareDataType 2>/dev/null \
      | awk -F': ' '/Model Name/ {print $2}' || true)"
  fi

  model_id="$(sysctl -n hw.model)"

  chip="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo 'unavailable')"

  ncpu="$(sysctl -n hw.ncpu)"

  if pcores="$(sysctl -n hw.perflevel0.physicalcpu 2>/dev/null)"; then
    ecores="$(sysctl -n hw.perflevel1.physicalcpu 2>/dev/null || echo 0)"
    cores="${ncpu} $(note "${pcores} performance + ${ecores} efficiency")"
  else
    cores="${ncpu} logical $(note "$(sysctl -n hw.physicalcpu) physical")"
  fi

  mem_gb=$(($(sysctl -n hw.memsize) / 1024 / 1024 / 1024))
  mem_free="$(memory_pressure 2>/dev/null | awk -F': ' '/free percentage/ {print $2}' || true)"

  batt="$(pmset -g batt 2>/dev/null \
    | sed -nE 's/.*InternalBattery.*[[:space:]]([0-9]+%); ([^;]+);.*/\1 \2/p' || true)"

  section 'Hardware'
  row 'Model' "${model_name:-unknown} $(note "${model_id}")"
  row 'Chip/CPU' "${chip}"
  row 'CPU Cores' "${cores}"
  row 'Memory' "${mem_gb} GB${mem_free:+ $(note "${mem_free} free")}"
  if [[ -n "${batt}" ]]; then
    row 'Battery' "${batt}"
  fi
}

printNetwork() {
  local route_out iface gateway port ip

  route_out="$(route -n get default 2>/dev/null || true)"
  iface="$(awk '/interface:/ {print $2}' <<<"${route_out}")"
  gateway="$(awk '/gateway:/ {print $2}' <<<"${route_out}")"

  section 'Network'
  if [[ -z "${iface}" ]]; then
    row 'Interface' 'none (no default route)'
    return
  fi

  port="$(networksetup -listallhardwareports 2>/dev/null \
    | awk -v dev="${iface}" '/^Hardware Port:/ {p = substr($0, 16)} /^Device:/ && $2 == dev {print p}' \
    || true)"

  ip="$(ipconfig getifaddr "${iface}" 2>/dev/null \
    || ifconfig "${iface}" 2>/dev/null | awk '/inet / && !seen {print $2; seen = 1}' \
    || true)"

  row 'Interface' "${iface}${port:+ $(note "${port}")}"
  row 'IP Address' "${ip:-unavailable}"
  row 'Gateway' "${gateway:-unavailable}"
}

lockdownState() {
  case "$(sysctl -n security.mac.lockdown_mode_state 2>/dev/null || true)" in
    1) echo 'enabled' ;;
    0) echo 'disabled' ;;
    *) echo 'unavailable' ;;
  esac
}

printSecurity() {
  local fw='/usr/libexec/ApplicationFirewall/socketfilterfw'

  section 'Security'
  row 'FileVault' "$(firstLine fdesetup status | sed -E 's/^FileVault is //; s/\.$//')"
  row 'Firewall' "$(firstLine "${fw}" --getglobalstate | sed -E 's/^Firewall is //; s/\. \(State = [0-9]+\)$//')"
  row 'Stealth Mode' "$(firstLine "${fw}" --getstealthmode | sed -E 's/^.*[Ss]tealth mode (is )?//; s/\.$//')"
  row 'Gatekeeper' "$(firstLine spctl --status | sed 's/^assessments //')"
  row 'SIP' "$(firstLine csrutil status | sed -E 's/^System Integrity Protection status: //; s/\.$//')"
  row 'Lockdown Mode' "$(lockdownState)"
  row 'XProtect' "$(firstLine xprotect version | sed -E 's/^Version: //; s/ Installed: / · installed /')"
}

printStorage() {
  local volume='/System/Volumes/Data' fs size used avail cap _

  section 'Storage'
  read -r fs size used avail cap _ <<<"$(df -H "${volume}" 2>/dev/null | awk 'NR==2' || true)"
  if [[ -z "${fs}" ]]; then
    row 'Disk' 'unavailable'
    return
  fi

  row 'Disk' "${used} used · ${avail} free · ${size} total $(note "${cap} full")"
  row 'Volume' "${volume} $(note "${fs}")"
}

main() {
  requireMacos
  banner "$(scutil --get ComputerName 2>/dev/null || hostname)" "$(date '+%Y-%m-%d %H:%M %Z')"
  printSystem
  printHardware
  printNetwork
  printSecurity
  printStorage
  printf '\n'
}

main "$@"
