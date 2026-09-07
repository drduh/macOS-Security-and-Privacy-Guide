#!/usr/bin/env bash
# https://github.com/drduh/macOS-Security-and-Privacy-Guide/blob/main/scripts/printSystemInfo.sh

set -o errexit
set -o nounset
set -o pipefail

requireMacos() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    printf 'script requires macOS\n' >&2
    exit 1
  fi
}

printOs() {
  printf 'System:           %s\n' "$(sw_vers -productName)"
  printf 'Version:          %s\n' "$(sw_vers -productVersion)"
  printf 'Build:            %s\n' "$(sw_vers -buildVersion)"
  printf 'Kernel:           %s\n' "$(uname -v)"
}

printHardware() {
  printf 'Model:            %s\n'    "$(sysctl -n hw.model)"
  printf 'Chip/CPU:         %s\n'    "$(sysctl -n machdep.cpu.brand_string 2>/dev/null || sysctl -n hw.model)"
  printf 'CPU Cores:        %s\n'    "$(sysctl -n hw.ncpu)"
  printf 'Memory:           %s GB\n' "$(( $(sysctl -n hw.memsize) / 1024 / 1024 / 1024 ))"
}

printNetwork() {
  printf 'Hostname:         %s\n' "$(scutil --get ComputerName 2>/dev/null || hostname)"
  printf 'IP Address:       %s\n' "$(ipconfig getifaddr en0 2>/dev/null || echo "unavailable")"
}

printUptime() {
  printf 'Uptime:           %s\n' "$(uptime)"
}

printFilevault() {
  printf 'Filevault:        %s\n' "$(fdesetup status 2>/dev/null || echo "unavailable")"
}

printFirewall() {
  local state
  state="$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unavailable")"
  printf 'Firewall:         %s\n' "${state}"
}

printGatekeeper() {
  printf 'Gatekeeper:       %s\n' "$(spctl --status 2>/dev/null || echo "unavailable")"
}

printSip() {
  printf 'SIP:              %s\n' "$(csrutil status 2>/dev/null || echo "unavailable")"
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
  printDisk
  printf '\n'
}

main "$@"
