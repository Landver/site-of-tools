#!/usr/bin/env bash
# Download the IP2Location LITE databases into iptolocation/assets/.
# Requires IP2LOCATION_DOWNLOAD_TOKEN in .env. Files that already exist are
# skipped. Downloads are ZIPs containing a .BIN.
#
# NOTE: verify the `file=` product codes against your IP2Location account's
# download page if a download 404s — LITE product codes occasionally change.
set -euo pipefail

cd "$(dirname "$0")/.."
[ -f .env ] && set -a && . ./.env && set +a

: "${IP2LOCATION_DOWNLOAD_TOKEN:?set IP2LOCATION_DOWNLOAD_TOKEN in .env}"
BASE="https://www.ip2location.com/download/?token=${IP2LOCATION_DOWNLOAD_TOKEN}"

# dest_path|product_code|bin_name_inside_zip
targets=(
  "iptolocation/assets/ipv4|DB11LITEBIN|IP2LOCATION-LITE-DB11.BIN"
  "iptolocation/assets/ipv6|DB11LITEBINIPV6|IP2LOCATION-LITE-DB11.IPV6.BIN"
  "iptolocation/assets/asn|DBASNLITE|IP2LOCATION-LITE-ASN.BIN"
  "iptolocation/assets/asn|DBASNLITEIPV6|IP2LOCATION-LITE-ASN.IPV6.BIN"
)

for t in "${targets[@]}"; do
  IFS='|' read -r dir code bin <<<"$t"
  mkdir -p "$dir"
  if [ -f "$dir/$bin" ]; then
    echo "skip  $dir/$bin (exists)"
    continue
  fi
  echo "fetch $bin (code=$code)"
  tmp="$(mktemp).zip"
  curl -fsSL -o "$tmp" "${BASE}&file=${code}"
  unzip -o -j "$tmp" "$bin" -d "$dir"
  rm -f "$tmp"
done

echo "done."
