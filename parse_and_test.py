import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import glob
import json
import operator
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import requests
import yaml

# Безопасные тайминги и лимиты
MAX_PING = 3500
MAX_WORKING = 60
MAX_WORKERS = 6
FLUSH_BATCH_SIZE = 5
BASE_PORT = 9100
MAX_RUNTIME_SECONDS = 2700
MAX_BAD_DAYS = 5

DELAY_TIMEOUT_MS = 8000
HTTP_DELAY_TIMEOUT_SEC = 10.0
SUB_DOWNLOAD_TIMEOUT_SEC = 25
WAVE_COOLDOWN_SEC = 1.5

SUBSCRIBES_FILE = "subscribes.txt"
FINAL_FILE = "final.txt"
CURSOR_FILE = "sub_cursor.txt"
SUB_STATS_FILE = "sub_stats.json"

TMP_BASE_DIR = "/tmp" if os.path.isdir("/tmp") else tempfile.gettempdir()
WORK_TMP_DIR = os.path.join(TMP_BASE_DIR, "mihomo_checker")

TEST_URL = base64.b64decode("aHR0cHM6Ly9jcC5jbG91ZGZsYXJlLmNvbS9nZW5lcmF0ZV8yMDQ=").decode("utf-8")
TEST_URL2 = base64.b64decode("aHR0cHM6Ly9nc3RhdGljLmNvbS9nZW5lcmF0ZV8yMDQ=").decode("utf-8")
LOCAL_API_HOST = base64.b64decode("aHR0cDovLzEyNy4wLjAuMQ==").decode("utf-8")

BUILTIN_PROXY_NAMES = {"DIRECT", "REJECT", "GLOBAL", "COMPATIBLE", "PASS", "AUTO"}
BLOCKED_SCHEMES = ("ss://", "ssr://", "wg://", "wireguard://")


def cleanup_temp_artifacts(recreate=True):
    """Зачищает /tmp/mihomo_checker и старые хвосты при старте и при выходе."""
    shutil.rmtree(WORK_TMP_DIR, ignore_errors=True)
    for pattern in (
        os.path.join(TMP_BASE_DIR, "mihomo_pool_*"),
        "sub_*.txt",
        "mihomo_*.yaml",
        "tested.txt",
        "testing.txt",
        "test.txt",
        "fail_counts.json",
    ):
        for path in glob.glob(pattern):
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    os.remove(path)
            except Exception:
                pass
    if recreate:
        os.makedirs(WORK_TMP_DIR, exist_ok=True)


def log_debug(msg):
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    with open("debug_log.txt", "a", encoding="utf-8") as f:
        f.write(line + "\n")


def set_github_output(name, value):
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a", encoding="utf-8") as f:
            f.write(f"{name}={value}\n")


def decode_base64_safe(data):
    try:
        cleaned = data.lstrip("\ufeff").strip()
        cleaned = re.sub(r"\s+", "", cleaned).replace("-", "+").replace("_", "/")
        if not cleaned:
            return ""
        cleaned = cleaned.rstrip("=")
        missing_padding = len(cleaned) % 4
        if missing_padding:
            cleaned += "=" * (4 - missing_padding)
        return base64.b64decode(cleaned).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def load_existing_final():
    """Загружает существующие серверы из final.txt в их оригинальном виде."""
    existing = {}
    if os.path.exists(FINAL_FILE):
        with open(FINAL_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                uri = line.lstrip("\ufeff").strip()
                if uri and "://" in uri and not uri.startswith("#") and uri not in existing:
                    existing[uri] = 1
    return existing


def save_final_pool(records):
    """Сохраняет серверы в final.txt до MAX_WORKING в их оригинальном виде."""
    items = [(ping, uri) for uri, ping in records.items()]
    items.sort(key=operator.itemgetter(0))
    selected = items[:MAX_WORKING]

    with open(FINAL_FILE, "w", encoding="utf-8") as f:
        for _, orig_uri in selected:
            f.write(f"{orig_uri}\n")

    return {uri: ping for ping, uri in selected}
def build_uri_name_map(raw_text):
    """Строит карту 'имя_ноды_в_mihomo -> исходная_строка' из текста подписки без изменения самих строк."""
    text = raw_text.lstrip("\ufeff").strip()
    if "://" not in text:
        decoded = decode_base64_safe(text)
        if decoded and "://" in decoded:
            text = decoded

    name_to_uris = {}
    all_uris = []

    for line in text.splitlines():
        uri = line.strip()
        if not uri or uri.startswith("#") or "://" not in uri:
            continue
        lower = uri.lower()
        if lower.startswith(("http://", "https://", "happ://", "tg://")):
            continue
        if lower.startswith(BLOCKED_SCHEMES):
            continue

        all_uris.append(uri)
        node_name = ""
        if lower.startswith("vmess://"):
            body, _, _ = uri[8:].partition("#")
            try:
                d = json.loads(decode_base64_safe(body))
                if str(d.get("tls", "")).lower() not in ("tls", "1", "true"):
                    all_uris.pop()
                    continue
                node_name = str(d.get("ps", "")).strip()
            except Exception:
                pass
        elif "#" in uri:
            _, _, raw_tag = uri.rpartition("#")
            node_name = urllib.parse.unquote(raw_tag).strip()

        if node_name:
            name_to_uris.setdefault(node_name, []).append(uri)

    return name_to_uris, all_uris

def test_delay_via_mihomo_api(api_port, node_name, encoded_test_url, slot_id):
    """Замеряет задержку конкретной ноды через API уже запущенного mihomo."""
    time.sleep((slot_id % MAX_WORKERS) * 0.2)
    encoded_name = urllib.parse.quote(node_name, safe="")
    check_url = (
        f"{LOCAL_API_HOST}:{api_port}/proxies/{encoded_name}/delay"
        f"?timeout={DELAY_TIMEOUT_MS}&url={encoded_test_url}&expected=204"
    )
    try:
        r = requests.get(check_url, timeout=HTTP_DELAY_TIMEOUT_SEC)
        if r.status_code == 200:
            data = r.json()
            if "delay" in data:
                ping = int(data["delay"])
                if 0 < ping < MAX_PING:
                    return node_name, ping, "OK"
                return node_name, ping, f"HIGH_PING({ping})"
        return node_name, 0, f"HTTP_{r.status_code}"
    except Exception as e:
        return node_name, 0, f"ERR:{e}"


def fetch_and_test_subscription_with_mihomo(sub_url, records, test_url, pass_label):
    """Скармливает URL подписки напрямую в mihomo (type: http). Возвращает (records, total_parsed_by_mihomo, added_count)."""
    api_port = BASE_PORT
    cfg_path = os.path.join(WORK_TMP_DIR, "sub_check_cfg.yaml")
    prov_path = os.path.join(WORK_TMP_DIR, "sub_check_prov.yaml")

    for p in (cfg_path, prov_path):
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass

    # Скачиваем текст подписки только чтобы сопоставить имена нод с оригинальными строками
    raw_sub_text = ""
    try:
        r_sub = requests.get(sub_url, timeout=SUB_DOWNLOAD_TIMEOUT_SEC)
        if r_sub.status_code == 200:
            raw_sub_text = r_sub.text
    except Exception:
        pass

    name_to_uris, _ = build_uri_name_map(raw_sub_text) if raw_sub_text else ({}, [])

    temp_config = {
        "external-controller": f"127.0.0.1:{api_port}",
        "log-level": "silent",
        "dns": {
            "enable": True,
            "ipv6": False,
            "nameserver": ["1.1.1.1", "8.8.8.8"]
        },
        "proxy-providers": {
            "sub_prov": {
                "type": "http",
                "url": sub_url,
                "path": prov_path,
                "interval": 3600,
                "health-check": {
                    "enable": False
                }
            }
        },
        "proxy-groups": [
            {
                "name": "AUTO",
                "type": "select",
                "use": ["sub_prov"]
            }
        ]
    }

    proc = None
    added_count = 0
    total_mihomo_nodes = 0

    try:
        with open(cfg_path, "w", encoding="utf-8") as f:
            yaml.dump(temp_config, f, allow_unicode=True)

        proc = subprocess.Popen(
            ["./mihomo", "-d", ".", "-f", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Ждем, пока сам mihomo скачает и распарсит подписку (до 20 секунд)
        mihomo_proxies = []
        for _ in range(40):
            time.sleep(0.5)
            if proc.poll() is not None:
                return records, 0, 0
            try:
                r_p = requests.get(f"{LOCAL_API_HOST}:{api_port}/providers/proxies/sub_prov", timeout=3)
                if r_p.status_code == 200:
                    raw_list = r_p.json().get("proxies", [])
                    mihomo_proxies = [
                        p for p in raw_list
                        if isinstance(p, dict) and p.get("name") and p.get("name") not in BUILTIN_PROXY_NAMES
                    ]
                    if mihomo_proxies:
                        break
            except Exception:
                continue

        total_mihomo_nodes = len(mihomo_proxies)
        if total_mihomo_nodes == 0:
            return records, 0, 0

        log_debug(f"[{pass_label}] Mihomo загрузил нод из подписки: {total_mihomo_nodes}")
        # Отбираем ноды, которых еще нет в final.txt, и отсекаем блокируемые типы по данным самого mihomo
        candidates = []
        used_uri_indices = {}

        for p_obj in mihomo_proxies:
            m_name = p_obj.get("name", "").strip()
            m_type = str(p_obj.get("type", "")).lower()
            if m_type in ("ss", "ssr", "wireguard"):
                continue

            # Убираем числовой суффикс дубликата ("Имя 1" -> "Имя"), если mihomo его добавил
            base_name = re.sub(r"\s+\d+$", "", m_name).strip()
            matched_uri = None

            for lookup_key in (m_name, base_name):
                uri_list = name_to_uris.get(lookup_key)
                if uri_list:
                    idx_u = used_uri_indices.get(lookup_key, 0)
                    if idx_u < len(uri_list):
                        matched_uri = uri_list[idx_u]
                        used_uri_indices[lookup_key] = idx_u + 1
                    else:
                        matched_uri = next(iter(uri_list))
                    break

            if matched_uri and matched_uri not in records:
                candidates.append((m_name, matched_uri))

        if not candidates:
            return records, total_mihomo_nodes, 0

        encoded_test_url = urllib.parse.quote(test_url, safe="")
        unflushed_count = 0

        for start_idx in range(0, len(candidates), MAX_WORKERS):
            if len(records) >= MAX_WORKING:
                break

            wave = candidates[start_idx:start_idx + MAX_WORKERS]
            uri_by_mname = {m_n: u for m_n, u in wave}

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [
                    executor.submit(test_delay_via_mihomo_api, api_port, m_n, encoded_test_url, slot)
                    for slot, (m_n, _) in enumerate(wave)
                ]
                for future in as_completed(futures):
                    m_n, ping, status = future.result()
                    orig_uri = uri_by_mname.get(m_n)
                    if status == "OK" and orig_uri and orig_uri not in records:
                        records[orig_uri] = ping
                        added_count += 1
                        unflushed_count += 1
                        log_debug(f"[{pass_label} OK {ping}ms] ({len(records)}/{MAX_WORKING}) {orig_uri[:55]}")

                        if unflushed_count >= FLUSH_BATCH_SIZE:
                            records = save_final_pool(records)
                            unflushed_count = 0
                            log_debug(f"[{pass_label}] Сохранено в {FINAL_FILE}: {len(records)}/{MAX_WORKING}")

            if len(records) < MAX_WORKING and (start_idx + MAX_WORKERS) < len(candidates):
                time.sleep(WAVE_COOLDOWN_SEC)

        if unflushed_count > 0:
            records = save_final_pool(records)
            log_debug(f"[{pass_label}] Сохранен остаток в {FINAL_FILE}: {len(records)}/{MAX_WORKING}")

    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()

    return records, total_mihomo_nodes, added_count
def read_cursor():
    if os.path.exists(CURSOR_FILE):
        try:
            with open(CURSOR_FILE, "r", encoding="utf-8") as f:
                val = f.read().strip()
                if val.isdigit():
                    return int(val)
        except Exception:
            pass
    return 0


def write_cursor(idx):
    with open(CURSOR_FILE, "w", encoding="utf-8") as f:
        f.write(str(idx))


def load_sub_stats():
    if os.path.exists(SUB_STATS_FILE):
        try:
            with open(SUB_STATS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_sub_stats(stats):
    with open(SUB_STATS_FILE, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)


def parse_sub_line(stripped):
    if re.match(r"^BAD!_00(?:\s+|$)", stripped, re.IGNORECASE):
        return True, 0, stripped
    m = re.match(r"^BAD!(?:_(\d{1,2}))?\s+(.*)$", stripped, re.IGNORECASE)
    if m:
        days = int(m.group(1)) if m.group(1) else 1
        clean_rest = m.group(2).strip()
        return False, days, clean_rest
    return False, 0, stripped


def is_line_active(line):
    s = line.strip()
    if not s or s.startswith("#"):
        return False
    perm_bad, _, _ = parse_sub_line(s)
    return not perm_bad


def normalize_github_url(url):
    if "://github.com" in url and "/blob/" in url:
        return url.replace("://github.com", "://://githubusercontent.com").replace("/blob/", "/")
    return url


def run_subscription_pass(
    sub_lines, sub_stats, records, start_time, today_str, test_url, pass_label, dead_urls_cache
):
    total_lines = len(sub_lines)
    cursor = read_cursor()
    if cursor >= total_lines:
        cursor = 0

    checked_this_pass = 0
    timed_out = False

    while len(records) < MAX_WORKING and checked_this_pass < total_lines:
        if time.time() - start_time > MAX_RUNTIME_SECONDS:
            log_debug(f"[{pass_label}] Достигнут лимит времени работы (45 мин). Продолжим в следующем запуске.")
            timed_out = True
            break

        idx = cursor
        cursor = (cursor + 1) % total_lines
        checked_this_pass += 1

        raw_line = sub_lines[idx]
        stripped = raw_line.strip()

        if not stripped or stripped.startswith("#"):
            write_cursor(cursor)
            continue

        perm_bad, curr_days, clean_line = parse_sub_line(stripped)
        if perm_bad:
            write_cursor(cursor)
            continue

        url_match = re.search(r"https?://[^\s]+", clean_line)
        if not url_match:
            write_cursor(cursor)
            continue

        orig_url = url_match.group(0)
        if orig_url in dead_urls_cache:
            write_cursor(cursor)
            continue

        fetch_url = normalize_github_url(orig_url)
        log_debug(f"[{pass_label}] Подписка [{idx + 1}/{total_lines}] (сбоев: {curr_days} дн.): {orig_url[:60]}")

        records, total_found_any, added_from_sub = fetch_and_test_subscription_with_mihomo(
            fetch_url, records, test_url, pass_label
        )

        ending = "\n" if raw_line.endswith("\n") else ""

        if total_found_any > 0:
            if curr_days > 0:
                log_debug(f"[{pass_label}] Подписка живая ({total_found_any} нод)! Снимаем метку BAD! с {orig_url[:55]}")
            else:
                log_debug(f"[{pass_label}] Подписка живая (+{added_from_sub} в пул). В final.txt: {len(records)}/{MAX_WORKING}")
            sub_lines[idx] = f"{clean_line}{ending}"
            sub_stats.pop(orig_url, None)
        else:
            dead_urls_cache.add(orig_url)
            entry = sub_stats.get(orig_url, {"days": curr_days, "last_fail_date": ""})
            days = max(curr_days, int(entry.get("days", 0)))
            if entry.get("last_fail_date") != today_str:
                days += 1
                entry["last_fail_date"] = today_str
            elif days == 0:
                days = 1
                entry["last_fail_date"] = today_str
            entry["days"] = days
            sub_stats[orig_url] = entry

            if days > MAX_BAD_DAYS:
                log_debug(f"[{pass_label}] Более {MAX_BAD_DAYS} дней сбоев -> бан BAD!_00: {orig_url[:55]}")
                sub_lines[idx] = f"BAD!_00 {clean_line}{ending}"
            else:
                tag = f"BAD!_{days:02d}"
                log_debug(f"[{pass_label}] Подписка пуста/недоступна -> {tag}: {orig_url[:55]}")
                sub_lines[idx] = f"{tag} {clean_line}{ending}"

        with open(SUBSCRIBES_FILE, "w", encoding="utf-8") as f:
            f.writelines(sub_lines)
        save_sub_stats(sub_stats)
        write_cursor(cursor)

    return records, timed_out


def main():
    cleanup_temp_artifacts(recreate=True)

    with open("debug_log.txt", "w", encoding="utf-8") as f:
        f.write("=== СТАРТ ПОПОЛНЕНИЯ FINAL.TXT ===\n")

    try:
        start_time = time.time()
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        records = load_existing_final()
        log_debug(f"В текущем {FINAL_FILE} уже есть серверов: {len(records)}/{MAX_WORKING}")

        if len(records) >= MAX_WORKING:
            log_debug("Список уже полон (60/60). Новые серверы не требуются.")
            set_github_output("has_more", "false")
            return

        if not os.path.exists(SUBSCRIBES_FILE):
            log_debug(f"Файл {SUBSCRIBES_FILE} не найден.")
            set_github_output("has_more", "false")
            return

        with open(SUBSCRIBES_FILE, "r", encoding="utf-8", errors="ignore") as f:
            sub_lines = f.readlines()

        if not sub_lines:
            set_github_output("has_more", "false")
            return

        if not any(is_line_active(l) for l in sub_lines):
            log_debug("В subscribes.txt не осталось рабочих подписок (все помечены BAD!_00).")
            set_github_output("has_more", "false")
            return

        sub_stats = load_sub_stats()
        records = save_final_pool(records)
        dead_urls_cache = set()

        log_debug("=== ПРОХОД 1 (TEST_URL) ===")
        records, timed_out = run_subscription_pass(
            sub_lines, sub_stats, records, start_time, today_str, TEST_URL, "TEST1", dead_urls_cache
        )

        if len(records) < MAX_WORKING and not timed_out:
            log_debug("=== ПРОХОД 2 (TEST_URL2) ===")
            records, timed_out = run_subscription_pass(
                sub_lines, sub_stats, records, start_time, today_str, TEST_URL2, "TEST2", dead_urls_cache
            )

        still_active = any(is_line_active(l) for l in sub_lines)
        if timed_out and len(records) < MAX_WORKING and still_active:
            set_github_output("has_more", "true")
        else:
            set_github_output("has_more", "false")
    finally:
        cleanup_temp_artifacts(recreate=False)


if __name__ == "__main__":
    main()
