#!/bin/bash
# https://github.com/drduh/macOS-Security-and-Privacy-Guide/blob/main/scripts/printKeychainCerts.sh
# Print certificate details from a macOS keychain, sorted by expiration.
#
# Usage:
#   ./printKeychainCerts.sh [keychain]
#
# keychain options:
#   - "rootca" (default) - /System/Library/Keychains/SystemRootCertificates.keychain
#   - "system"           - /Library/Keychains/System.keychain

#set -x  # uncomment to debug
set -o errtrace
set -o nounset
set -o pipefail

umask 077
export LC_ALL="C"

resolveKeychain() {
  local requested="${1:-rootca}"
  local keychain

  case "$requested" in
    rootca|root|roots|r|ca|cas|c)
      keychain="/System/Library/Keychains/SystemRootCertificates.keychain"
      ;;
    system|sys|s)
      keychain="/Library/Keychains/System.keychain"
      ;;
    *)
      echo "unknown keychain '$requested' - use 'rootca' or 'system'" >&2
      return 1
      ;;
  esac

  if [[ ! -e "$keychain" ]]; then
    echo "keychain '$keychain' not found" >&2
    return 1
  fi

  echo "$keychain"
}

exportCerts() {
  local keychain="$1"
  local pemFile="$2"
  security export -k "$keychain" -t certs -f pemseq -o "$pemFile"
}

splitCerts() {
  local pemFile="$1"
  local splitDir="$2"
  awk -v outdir="$splitDir" 'BEGIN{c=0}
    /-----BEGIN CERTIFICATE-----/{c++}
    {print > (outdir "/cert-" c ".pem")}' "$pemFile"
}

certToJson() {
  local certFile="$1"
  local info subject expires fingerprint

  info=$(openssl x509 -noout -subject -enddate -fingerprint -sha256 -in "$certFile")
  subject=$(echo "$info" | sed -n 's/^subject=[[:space:]]*//p')
  expires=$(echo "$info" | sed -n 's/^notAfter=//p')
  fingerprint=$(echo "$info" | sed -n 's/^[Ss][Hh][Aa]256 Fingerprint=//p')

  jq -n --arg subject "$subject" \
        --arg expires "$expires" \
        --arg fp "$fingerprint" \
    '{"subject": $subject, "expires": $expires, "sha-256": $fp}'
}

printCertsSortedByDate() {
  jq -s 'sort_by(.expires | rtrimstr(" GMT") |
    strptime("%b %d %H:%M:%S %Y") | mktime) | .[]'
}

main() {
  local workDir pemFile keychain
  keychain=$(resolveKeychain "${1:-rootca}") || exit 1

  workDir=$(mktemp -d)
  pemFile="$workDir/certs.pem"

  exportCerts "$keychain" "$pemFile"
  splitCerts "$pemFile" "$workDir"

  for f in "$workDir"/cert-*.pem; do
    certToJson "$f"
  done | printCertsSortedByDate
}

main "$@"
