#!/usr/bin/env bash
# Архив, IPA и (по флагу) загрузка в App Store Connect.
#
#   ASC_KEY_ID=… ASC_ISSUER_ID=… ASC_KEY_PATH=…/AuthKey_….p8 \
#     ios/scripts/build-release.sh <build-number> [--upload]
#
# Ключ App Store Connect API берётся только из окружения: в репозитории его нет и не
# будет. Подпись — автоматическая, командой 5T376DA4G7 (docs/adr/0015).
set -euo pipefail

BUILD="${1:?usage: build-release.sh <build-number> [--upload]}"
UPLOAD="${2:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORK="${FORK_DIR:-$HERE/../android/simplex-chat}"
IOS="$FORK/apps/ios"
OUT="$HERE/build/$BUILD"
TEAM=5T376DA4G7

[[ "$BUILD" =~ ^[0-9]+$ ]] || { echo "номер сборки — целое число, строго растущее" >&2; exit 1; }
: "${ASC_KEY_ID:?нужен ASC_KEY_ID}" "${ASC_ISSUER_ID:?нужен ASC_ISSUER_ID}" "${ASC_KEY_PATH:?нужен ASC_KEY_PATH}"
[ -f "$ASC_KEY_PATH" ] || { echo "нет ключа $ASC_KEY_PATH" >&2; exit 1; }

bash "$HERE/scripts/sync-overlay.sh"

# Те же гейты, что у Android (android/scripts/build-release.sh): сборку, которую нечем
# сопоставить с исходниками, людям не отдаём.
[ -f "$IOS/SimpleXChat/Hearth/Resources/hearth_node.json" ] || { echo "не вшит узел — ios/scripts/bake-node.sh" >&2; exit 1; }
ls "$IOS"/Libraries/ios/libHSsimplex-chat-*.a >/dev/null 2>&1 || { echo "нет ядра — ios/scripts/build-core.sh device" >&2; exit 1; }
DIRTY="$(git -C "$FORK" status --porcelain)"
if [ -n "$DIRTY" ] && [ "${HEARTH_ALLOW_DIRTY:-0}" != "1" ]; then
    echo "дерево форка изменено после sync-overlay — закоммитьте и перевыпустите патчи:" >&2
    printf '%s\n' "$DIRTY" >&2
    exit 1
fi

(cd "$FORK" && sh scripts/ios/update-version.sh "$BUILD" "$(grep -m1 -oE 'MARKETING_VERSION = [0-9.]+' "$IOS/SimpleX.xcodeproj/project.pbxproj" | cut -d' ' -f3)")

AUTH=(-allowProvisioningUpdates
      -authenticationKeyPath "$ASC_KEY_PATH"
      -authenticationKeyID "$ASC_KEY_ID"
      -authenticationKeyIssuerID "$ASC_ISSUER_ID")

mkdir -p "$OUT"
echo "== archive"
xcodebuild -project "$IOS/SimpleX.xcodeproj" -scheme "SimpleX (iOS)" -configuration Release \
    -destination 'generic/platform=iOS' -archivePath "$OUT/Hearth.xcarchive" \
    DEVELOPMENT_TEAM="$TEAM" "${AUTH[@]}" archive

DESTINATION=export
[ "$UPLOAD" = "--upload" ] && DESTINATION=upload
cat > "$OUT/ExportOptions.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key><string>app-store-connect</string>
    <key>destination</key><string>$DESTINATION</string>
    <key>teamID</key><string>$TEAM</string>
    <key>signingStyle</key><string>automatic</string>
    <key>manageAppVersionAndBuildNumber</key><false/>
</dict>
</plist>
PLIST

echo "== export ($DESTINATION)"
xcodebuild -exportArchive -archivePath "$OUT/Hearth.xcarchive" \
    -exportOptionsPlist "$OUT/ExportOptions.plist" -exportPath "$OUT/export" "${AUTH[@]}"

# Паспорт сборки: по нему сборка сопоставляется с исходниками без переписки.
{
    echo "fork_commit=$(git -C "$FORK" rev-parse HEAD)"
    echo "build=$BUILD"
    echo "destination=$DESTINATION"
    find "$OUT/export" -name '*.ipa' -exec sh -c 'echo "ipa_sha256=$(shasum -a 256 "$1" | cut -d" " -f1)"' _ {} \;
    sed 's/^/core_/' "$IOS/Libraries/ios/SHA256SUMS" 2>/dev/null || echo "core=без SHA256SUMS"
    echo "node=$(cat "$IOS/SimpleXChat/Hearth/Resources/hearth_node.json")"
    echo "xcode=$(xcodebuild -version | tr '\n' ' ')"
} > "$OUT/build-info.txt"
cat "$OUT/build-info.txt"
