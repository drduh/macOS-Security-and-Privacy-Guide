#!/bin/bash
# https://github.com/drduh/macOS-Security-and-Privacy-Guide/blob/main/scripts/printCertAuthorities.sh
# Print certificate details from the system root keychain, sorted by expiration.

#set -x  # uncomment to debug
set -o errtrace
set -o nounset
set -o pipefail

umask 077
export LC_ALL="C"

KEYCHAIN="/System/Library/Keychains/SystemRootCertificates.keychain"

exportCerts() {
  local pemFile="$1"
  security export -k "$KEYCHAIN" -t certs -o "$pemFile"
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
  local subject expires fingerprint

  subject=$(openssl x509 -noout -subject -in "$certFile" | sed -E 's/^subject=[[:space:]]*//')
  expires=$(openssl x509 -noout -enddate -in "$certFile" | cut -d= -f2)
  fingerprint=$(openssl x509 -noout -fingerprint -sha256 -in "$certFile" | cut -d= -f2)

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
  local work_dir pemFile
  workDir=$(mktemp -d)
  pemFile="$workDir/root-certs.pem"

  exportCerts "$pemFile"
  splitCerts "$pemFile" "$workDir"

  for f in "$workDir"/cert-*.pem; do
    certToJson "$f"
  done | printCertsSortedByDate
}

main "$@"
