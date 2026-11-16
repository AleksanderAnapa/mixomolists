#!/bin/sh

GITHUB_TOKEN=""
REPO="AleksanderAnapa/mixomolists"
FILE_PATH="final.txt"

MAIN_API="http://192.168.7.1:9090"
PROVIDER_NAME="WAN1"
MAX_PING=400
MAX_FAILS=5

STATS_FILE="/tmp/mihomo_fail_stats.json"
WORK_DIR="/tmp/gh_check"
LOCK_FILE="/tmp/gh_check.lock"

RAW_BASE=$(printf "%s" "aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29t" | base64 -d)
API_BASE=$(printf "%s" "aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcw==" | base64 -d)

if [ -f "$LOCK_FILE" ] && kill -0 "$(cat "$LOCK_FILE")" 2>/dev/null; then
    exit 0
fi
echo $$ > "$LOCK_FILE"
trap 'rm -rf "$WORK_DIR" "$LOCK_FILE"' EXIT

mkdir -p "$WORK_DIR"
cd "$WORK_DIR" || exit 1

[ ! -f "$STATS_FILE" ] && echo "{}" > "$STATS_FILE"

# 1. Скачиваем свежий final.txt с GitHub (сначала через API без кэша CDN, затем Raw)
curl -skL --max-time 15 \
    -H "Authorization: Bearer ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github.raw+json" \
    "${API_BASE}/${REPO}/contents/${FILE_PATH}" -o "$WORK_DIR/final.txt"

if ! grep -qE "^(vless|vmess|trojan)://" "$WORK_DIR/final.txt" 2>/dev/null; then
    curl -skL --max-time 15 "${RAW_BASE}/${REPO}/main/${FILE_PATH}?t=$(date +%s)" -o "$WORK_DIR/final.txt"
fi

if ! grep -qE "^(vless|vmess|trojan)://" "$WORK_DIR/final.txt" 2>/dev/null; then
    exit 0
fi

# 2. Получаем из основного Mihomo текущие результаты фонового health-check провайдера WAN1
curl -s --max-time 5 "${MAIN_API}/providers/proxies/${PROVIDER_NAME}" > "$WORK_DIR/wan_state.json"

# Если WAN1 пуст или не отвечает — выходим, чтобы не портить статистику
loaded_count=$(jq -r '.proxies | length // 0' "$WORK_DIR/wan_state.json" 2>/dev/null || echo 0)
if [ "$loaded_count" -eq 0 ] 2>/dev/null; then
    exit 0
fi

# Выгружаем карту "имя_узла -> последний_пинг"
jq -r '.proxies[]? | "\(.name)|\(.history[-1].delay // 0)"' "$WORK_DIR/wan_state.json" > "$WORK_DIR/pings.txt"

decode_b64() {
    echo "$1" | tr -d '\r\n ' | awk '{
        len = length($0) % 4;
        if (len == 2) print $0 "==";
        else if (len == 3) print $0 "=";
        else print $0;
    }' | base64 -d 2>/dev/null
}

# 3. Обновляем счетчики ошибок для каждого сервера и оставляем те, у кого < 5 неудач
: > "$WORK_DIR/kept.txt"
cp "$STATS_FILE" "$WORK_DIR/new_stats.json"

total_before=0
total_after=0
removed_count=0

while IFS= read -r orig_uri; do
    orig_uri=$(echo "$orig_uri" | tr -d '\r')
    [ -z "$orig_uri" ] && continue
    total_before=$((total_before + 1))

    if echo "$orig_uri" | grep -q "^vmess://"; then
        b64=$(echo "${orig_uri#vmess://}" | awk -F'#' '{print $1}')
        p_name=$(decode_b64 "$b64" | jq -r '.ps // empty' 2>/dev/null)
    else
        p_name=$(echo "$orig_uri" | awk -F'#' '{print $NF}')
    fi

    delay=0
    if [ -n "$p_name" ]; then
        delay=$(awk -F'|' -v target="$p_name" '$1 == target {print $2; exit}' "$WORK_DIR/pings.txt")
        [ -z "$delay" ] && delay=0
    fi

    prev_fails=$(jq -r --arg key "$orig_uri" '.[$key] // 0' "$WORK_DIR/new_stats.json" 2>/dev/null || echo 0)

    if [ "$delay" -gt 0 ] 2>/dev/null && [ "$delay" -lt "$MAX_PING" ]; then
        # Сервер ответил быстро (< 400 мс) -> сбрасываем счетчик ошибок в 0
        curr_fails=0
    else
        # Таймаут или пинг >= 400 мс -> увеличиваем счетчик ошибок на 1
        curr_fails=$((prev_fails + 1))
    fi

    if [ "$curr_fails" -lt "$MAX_FAILS" ]; then
        echo "$orig_uri" >> "$WORK_DIR/kept.txt"
        total_after=$((total_after + 1))
        jq --arg key "$orig_uri" --argjson val "$curr_fails" '.[$key] = $val' "$WORK_DIR/new_stats.json" > "$WORK_DIR/tmp_stats.json" && mv "$WORK_DIR/tmp_stats.json" "$WORK_DIR/new_stats.json"
    else
        # Набрал 5 неудач подряд -> удаляем из списка и очищаем из статистики
        removed_count=$((removed_count + 1))
        jq --arg key "$orig_uri" 'del(.[$key])' "$WORK_DIR/new_stats.json" > "$WORK_DIR/tmp_stats.json" && mv "$WORK_DIR/tmp_stats.json" "$WORK_DIR/new_stats.json"
    fi
done < "$WORK_DIR/final.txt"

mv "$WORK_DIR/new_stats.json" "$STATS_FILE"

# 4. Если ни один сервер не был удален (никто еще не набрал 5 ошибок) — GitHub не трогаем
if [ "$removed_count" -eq 0 ]; then
    exit 0
fi

mv "$WORK_DIR/kept.txt" "$WORK_DIR/final.txt"

# 5. Отправляем обновленный final.txt на GitHub (даже если он стал пустым)
API_URL="${API_BASE}/${REPO}/contents/${FILE_PATH}"

SHA=$(curl -sk -H "Authorization: Bearer ${GITHUB_TOKEN}" \
     -H "Accept: application/vnd.github+json" \
     "$API_URL" | jq -r '.sha // empty')

if [ -s "$WORK_DIR/final.txt" ]; then
    CONTENT_B64=$(base64 "$WORK_DIR/final.txt" | tr -d '\r\n')
else
    CONTENT_B64=""
fi

if [ -n "$SHA" ]; then
    PAYLOAD=$(jq -n --arg msg "Router stats cleanup: removed ${removed_count}, left ${total_after}" --arg content "$CONTENT_B64" --arg sha "$SHA" \
        '{message: $msg, content: $content, sha: $sha}')
else
    PAYLOAD=$(jq -n --arg msg "Router stats cleanup: removed ${removed_count}, left ${total_after}" --arg content "$CONTENT_B64" \
        '{message: $msg, content: $content}')
fi

curl -sk -X PUT \
     -H "Authorization: Bearer ${GITHUB_TOKEN}" \
     -H "Accept: application/vnd.github+json" \
     -d "$PAYLOAD" \
     "$API_URL" >/dev/null 2>&1

# 6. Если в списке осталось больше 2 живых — обновляем провайдер WAN1 в основном Mihomo
if [ "$total_after" -gt 2 ]; then
    sleep 6
    curl -s -X PUT "${MAIN_API}/providers/proxies/${PROVIDER_NAME}" >/dev/null 2>&1
fi

: > "$WORK_DIR/final.txt"
