#!/usr/bin/env bash
# Раздача iOS без App Store — Ad Hoc по ссылке (ios/README.md, «Раздача Ad Hoc»).
#
#   ios/scripts/adhoc.sh devices                  — iPhone, на которые встанет сборка
#   ios/scripts/adhoc.sh add-device <имя> <UDID>  — добавить iPhone (лимит Apple — 100 в год)
#   ios/scripts/adhoc.sh publish <номер сборки>   — архив сборки → Ad Hoc со всеми
#                                                   устройствами → https://slow6r.github.io/hearth/
#
# После add-device нужен publish: устройство попадает в профиль только при новом экспорте.
# Нужны ASC_KEY_ID, ASC_ISSUER_ID, ASC_KEY_PATH — те же, что у build-release.sh.
# Секретов в репозитории нет: ключ лежит вне его, IPA уходит только на GitHub Pages.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEAM=5T376DA4G7
BUNDLE=ru.myhearth.chat
REPO_URL=https://github.com/slow6r/hearth.git
GH_REPO=slow6r/hearth
SITE=https://slow6r.github.io/hearth

: "${ASC_KEY_ID:?нужен ASC_KEY_ID}" "${ASC_ISSUER_ID:?нужен ASC_ISSUER_ID}" "${ASC_KEY_PATH:?нужен ASC_KEY_PATH}"

# App Store Connect API: asc METHOD PATH [JSON]. JWT живёт 15 минут — делаем на каждый вызов.
asc() {
    local tok
    tok=$(python3 - <<'PY'
import os, time, jwt
now = int(time.time())
print(jwt.encode({"iss": os.environ["ASC_ISSUER_ID"], "iat": now, "exp": now + 900,
                  "aud": "appstoreconnect-v1"},
                 open(os.environ["ASC_KEY_PATH"]).read(), algorithm="ES256",
                 headers={"kid": os.environ["ASC_KEY_ID"], "typ": "JWT"}))
PY
)
    local args=(-sS --fail-with-body --retry 4 --retry-all-errors --max-time 60
                -X "$1" -H "Authorization: Bearer $tok" -H "Content-Type: application/json")
    [ $# -ge 3 ] && args+=(-d "$3")
    curl "${args[@]}" "https://api.appstoreconnect.apple.com$2"
}

registered_udids() {
    asc GET "/v1/devices?limit=200&filter%5Bplatform%5D=IOS&filter%5Bstatus%5D=ENABLED" |
        python3 -c "import json,sys; [print(d['attributes']['udid']) for d in json.load(sys.stdin)['data']]" | sort
}

cmd_devices() {
    asc GET "/v1/devices?limit=200&filter%5Bplatform%5D=IOS" | python3 -c "
import json, sys
for d in json.load(sys.stdin)['data']:
    a = d['attributes']
    print(f\"{a['status']:8} {a['udid']}  {a.get('model') or '?':18} {a['name']}\")"
}

cmd_add_device() {
    local name="${1:?имя устройства}" udid="${2:?UDID}"
    # UDID iPhone: 40 hex (до iPhone XS) или 8 hex-8-16 hex (новые). Опечатка здесь —
    # потерянный слот из сотни, удалить устройство Apple даёт только раз в год.
    [[ "$udid" =~ ^[0-9A-Fa-f]{40}$ || "$udid" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}$ ]] ||
        { echo "не похоже на UDID iPhone: $udid" >&2; exit 1; }
    asc POST /v1/devices "{\"data\":{\"type\":\"devices\",\"attributes\":{\"name\":\"$name\",\"platform\":\"IOS\",\"udid\":\"$udid\"}}}" |
        python3 -c "import json,sys; a=json.load(sys.stdin)['data']['attributes']; print('добавлен:', a['name'], a['udid'], a['status'])"
    echo "теперь: ios/scripts/adhoc.sh publish <сборка> — без этого телефон в профиль не попадёт"
}

cmd_publish() {
    local build="${1:?номер сборки (каталог ios/build/<N>)}"
    local out="$HERE/build/$build" archive="$HERE/build/$build/Hearth.xcarchive"
    [ -d "$archive" ] || { echo "нет архива $archive — сначала build-release.sh $build" >&2; exit 1; }

    # Свежий профиль: старый Ad Hoc этого приложения удаляем, Xcode выпустит новый со всеми
    # устройствами. Чужие профили (в аккаунте есть другие приложения) не трогаем.
    asc GET "/v1/profiles?limit=200&filter%5BprofileType%5D=IOS_APP_ADHOC&fields%5Bprofiles%5D=name" |
        python3 -c "
import json, sys
for p in json.load(sys.stdin)['data']:
    if '$BUNDLE' in p['attributes']['name']: print(p['id'], p['attributes']['name'])" |
        while read -r id pname; do
            asc DELETE "/v1/profiles/$id" >/dev/null && echo "удалён старый профиль: $pname"
        done

    cat > "$out/ExportOptions-adhoc.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key><string>release-testing</string>
    <key>teamID</key><string>$TEAM</string>
    <key>signingStyle</key><string>automatic</string>
    <key>thinning</key><string>&lt;none&gt;</string>
</dict>
</plist>
PLIST
    rm -rf "$out/adhoc"
    xcodebuild -exportArchive -archivePath "$archive" -exportOptionsPlist "$out/ExportOptions-adhoc.plist" \
        -exportPath "$out/adhoc" -allowProvisioningUpdates -authenticationKeyPath "$ASC_KEY_PATH" \
        -authenticationKeyID "$ASC_KEY_ID" -authenticationKeyIssuerID "$ASC_ISSUER_ID" > "$out/adhoc-export.log" 2>&1 ||
        { tail -20 "$out/adhoc-export.log" >&2; exit 1; }
    local ipa
    ipa=$(find "$out/adhoc" -name '*.ipa' | head -1)

    # Проверка: в профиле все зарегистрированные iPhone, иначе кто-то не сможет поставить.
    local tmp
    tmp=$(mktemp -d)
    unzip -q -o "$ipa" 'Payload/*.app/embedded.mobileprovision' 'Payload/*.app/Info.plist' -d "$tmp"
    local app
    app=$(ls -d "$tmp"/Payload/*.app)
    security cms -D -i "$app/embedded.mobileprovision" > "$tmp/profile.plist"
    python3 - "$tmp/profile.plist" > "$tmp/provisioned" <<'PY'
import plistlib, sys
for u in plistlib.load(open(sys.argv[1], "rb")).get("ProvisionedDevices", []): print(u)
PY
    sort -o "$tmp/provisioned" "$tmp/provisioned"
    registered_udids > "$tmp/registered"
    local missing
    missing=$(comm -23 "$tmp/registered" "$tmp/provisioned")
    [ -z "$missing" ] || { echo "в профиль не попали устройства:" >&2; echo "$missing" >&2; exit 1; }
    local version build_no expires sha
    version=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$app/Info.plist")
    build_no=$(/usr/libexec/PlistBuddy -c 'Print CFBundleVersion' "$app/Info.plist")
    expires=$(python3 - "$tmp/profile.plist" <<'PY'
import plistlib, sys
m = ["января", "февраля", "марта", "апреля", "мая", "июня", "июля", "августа",
     "сентября", "октября", "ноября", "декабря"]
d = plistlib.load(open(sys.argv[1], "rb"))["ExpirationDate"]
print(f"{d.day} {m[d.month - 1]} {d.year}")
PY
)
    sha=$(shasum -a 256 "$ipa" | cut -d' ' -f1)
    echo "Ad Hoc: $version ($build_no), устройств в профиле: $(wc -l < "$tmp/provisioned" | tr -d ' '), работает до $expires"

    # Сайт: отдельная ветка gh-pages, каждый раз с нуля — старые IPA по 50 МБ в истории
    # не копятся. IPA на Pages, а не в релизе: установщик iOS берёт файл без редиректов.
    local site="$tmp/site" date_ru
    date_ru=$(python3 -c "
import datetime
m=['января','февраля','марта','апреля','мая','июня','июля','августа','сентября','октября','ноября','декабря']
d=datetime.date.today(); print(f'{d.day} {m[d.month-1]} {d.year}')")
    mkdir -p "$site"
    cp "$ipa" "$site/Hearth.ipa"
    local icons="$HERE/../android/simplex-chat/apps/ios/Shared/Assets.xcassets/AppIcon.appiconset"
    sips -z 57 57 "$icons/1024.png" --out "$site/icon-57.png" >/dev/null
    sips -z 512 512 "$icons/1024.png" --out "$site/icon-512.png" >/dev/null
    touch "$site/.nojekyll"
    fill() {
        sed -e "s|{{VERSION}}|$version|g" -e "s|{{BUILD}}|$build_no|g" -e "s|{{DATE}}|$date_ru|g" \
            -e "s|{{EXPIRES}}|$expires|g" -e "s|{{SHA256}}|$sha|g" -e "s|{{SITE}}|$SITE|g" \
            -e "s|{{MANIFEST_URL}}|$SITE/manifest.xml|g" -e "s|{{IPA_URL}}|$SITE/Hearth.ipa|g" "$1"
    }
    fill "$HERE/adhoc/index.html.in" > "$site/index.html"
    # .xml, а не .plist: Pages отдаёт .plist как application/octet-stream, а Apple для
    # манифеста установки просит XML-тип; .xml уходит как application/xml.
    fill "$HERE/adhoc/manifest.plist.in" > "$site/manifest.xml"
    plutil -lint "$site/manifest.xml" >/dev/null
    if grep -q '{{' "$site/index.html" "$site/manifest.xml"; then
        echo "незаполненные поля в шаблоне" >&2; exit 1
    fi

    (cd "$site" && git init -q -b gh-pages && git add -A &&
        git -c user.name="$(git -C "$HERE" config user.name)" -c user.email="$(git -C "$HERE" config user.email)" \
            commit -q -m "Hearth для iPhone $version ($build_no), Ad Hoc" &&
        git push -q -f "$REPO_URL" gh-pages)
    if ! gh api "repos/$GH_REPO/pages" >/dev/null 2>&1; then
        gh api -X POST "repos/$GH_REPO/pages" -f "source[branch]=gh-pages" -f "source[path]=/" >/dev/null
        echo "GitHub Pages включён"
    fi

    {
        echo "version=$version"
        echo "build=$build_no"
        echo "ipa_sha256=$sha"
        echo "devices=$(wc -l < "$tmp/provisioned" | tr -d ' ')"
        echo "profile_expires=$expires"
        echo "url=$SITE/"
        echo "published=$(date -u +%Y-%m-%dT%H:%MZ)"
    } > "$out/adhoc/publish-info.txt"
    rm -rf "$tmp"
    echo "выложено: $SITE/ (Pages обновляется 1–2 минуты)"
}

case "${1:-}" in
    devices) cmd_devices ;;
    add-device) shift; cmd_add_device "$@" ;;
    publish) shift; cmd_publish "$@" ;;
    *) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
