#!/usr/bin/env bash
# https://github.com/drduh/macOS-Security-and-Privacy-Guide/blob/main/scripts/printSystemInfo.sh

set -o errexit
set -o nounset
set -o pipefail

readonly LABEL_WIDTH=18

requireMacos() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    printf 'script requires macOS\n' >&2
    exit 1
  fi
}

row() {
  printf '%-*s%s\n' "${LABEL_WIDTH}" "$1:" "$2"
}

printOs() {
  row 'System'  "$(sw_vers -productName)"
  row 'Version' "$(sw_vers -productVersion)"
  row 'Build'   "$(sw_vers -buildVersion)"
  row 'Kernel'  "$(uname -v)"
}

printHardware() {
  local chip mem_gb
  chip="$(sysctl -n machdep.cpu.brand_string 2>/dev/null \
    || sysctl -n hw.model)"
  mem_gb="$(( $(sysctl -n hw.memsize) / 1024 / 1024 / 1024 ))"
  row 'Model'     "$(sysctl -n hw.model)"
  row 'Chip/CPU'  "${chip}"
  row 'CPU Cores' "$(sysctl -n hw.ncpu)"
  row 'Memory'    "${mem_gb} GB"
}

printNetwork() {
  local hostname ip
  hostname="$(scutil --get ComputerName 2>/dev/null || hostname)"
  ip="$(ipconfig getifaddr en0 2>/dev/null || echo "unavailable")"
  row 'Hostname'   "${hostname}"
  row 'IP Address' "${ip}"
}

printUptime() {
  row 'Uptime' "$(uptime)"
  row 'Last Boot' "$(sysctl -n kern.boottime | sed 's/.*} //')"
}

printFilevault() {
  row 'Filevault' "$(fdesetup status 2>/dev/null || echo "unavailable")"
}

printFirewall() {
  local state
  state="$(/usr/libexec/ApplicationFirewall/socketfilterfw \
    --getglobalstate 2>/dev/null || echo "unavailable")"
  row 'Firewall' "${state}"
}

printGatekeeper() {
  row 'Gatekeeper' "$(spctl --status 2>/dev/null || echo "unavailable")"
}

printSip() {
  row 'SIP' "$(csrutil status 2>/dev/null || echo "unavailable")"
}

printXProtect() {
  row 'XProtect' "$(xprotect version 2>/dev/null || echo "unavailable")"
}


printDisk() {
  df -H / | awk 'NR==1 || NR==2'
}

main() {
  requireMacos
  printUptime
  printOs
  printHardware
  printNetwork
  printFilevault
  printFirewall
  printGatekeeper
  printSip
  printXProtect
  printDisk
  printf '\n'
}

main "$@"
