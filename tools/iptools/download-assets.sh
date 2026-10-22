#!/usr/bin/env bash
# If a download 404s, re-check its product code on your IP2Location account's download page.
set -euo pipefail

cd "$(dirname "$0")/../.."
[ -f .env ] && set -a && . ./.env && set +a

: "${IP2LOCATION_DOWNLOAD_TOKEN:?set IP2LOCATION_DOWNLOAD_TOKEN in .env}"
BASE="https://www.ip2location.com/download/?token=${IP2LOCATION_DOWNLOAD_TOKEN}"

# dest_path|product_code|bin_name_inside_zip
targets=(
  "tools/iptools/assets/ipv4|DB11LITEBIN|IP2LOCATION-LITE-DB11.BIN"
  "tools/iptools/assets/ipv6|DB11LITEBINIPV6|IP2LOCATION-LITE-DB11.IPV6.BIN"
  "tools/iptools/assets/asn|DBASNLITEBIN|IP2LOCATION-LITE-ASN.BIN"
  "tools/iptools/assets/asn|DBASNLITEBINIPV6|IP2LOCATION-LITE-ASN.IPV6.BIN"
  # IP2Proxy PX12 (~1.6 GB); unzip -j extracts only the .BIN from the zip.
  "tools/iptools/assets/ip2proxy|PX12LITEBIN|IP2PROXY-LITE-PX12.BIN"
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
