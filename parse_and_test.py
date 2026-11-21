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

# Щадящие тайминги и лимиты для перегруженных серверов
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

# Фиксированная временная папка в /tmp
TMP_BASE_DIR = "/tmp" if os.path.isdir("/tmp") else tempfile.gettempdir()
WORK_TMP_DIR = os.path.join(TMP_BASE_DIR, "mihomo_checker")

TEST_URL = base64.b64decode("aHR0cHM6Ly9jcC5jbG91ZGZsYXJlLmNvbS9nZW5lcmF0ZV8yMDQ=").decode("utf-8")
TEST_URL2 = base64.b64decode("aHR0cHM6Ly9nc3RhdGljLmNvbS9nZW5lcmF0ZV8yMDQ=").decode("utf-8")
LOCAL_API_HOST = base64.b64decode("aHR0cDovLzEyNy4wLjAuMQ==").decode("utf-8")

URI_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]{1,20}://\S{4,}$")
BUILTIN_PROXY_NAMES = {"DIRECT", "REJECT", "GLOBAL", "COMPATIBLE", "PASS", "AUTO"}
NON_PROXY_SCHEMES = (
    "http://", "https://", "file://", "ftp://", "ftps://",
    "mailto:", "tg://", "javascript:", "data:", "ws://", "wss://"
)


def cleanup_temp_artifacts(recreate=True):
    """Сразу при старте и при выходе зачищает /tmp/mihomo_checker и любые старые хвосты от аварийных остановок."""
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
    """Безопасно декодирует Base64 целиком (включая многострочный и URL-safe) без порчи содержимого."""
    try:
        cleaned = data.lstrip("\ufeff").strip()
        cleaned = re.sub(r"\s+", "", cleaned).replace("-", "+").replace("_", "/")
        if len(cleaned) < 12:
            return ""
        if not re.fullmatch(r"[A-Za-z0-9+/=]+", cleaned):
            return ""
        cleaned = cleaned.rstrip("=")
        missing_padding = len(cleaned) % 4
        if missing_padding:
            cleaned += "=" * (4 - missing_padding)
        raw_bytes = base64.b64decode(cleaned, validate=False)
        decoded = raw_bytes.decode("utf-8", errors="ignore")
        return decoded if "://" in decoded else ""
    except Exception:
        return ""


def is_proxy_uri(line):
    """Отсекает пустые строки, комментарии, HTML, мусор и обычные веб-ссылки."""
    if not line or len(line) < 12 or len(line) > 8192:
        return False
    if line.startswith(("#", "//", "<", "{", "[", ";", "!")):
        return False
    if not URI_SCHEME_RE.match(line):
        return False
    lower = line.lower()
    if lower.startswith(NON_PROXY_SCHEMES):
        return False
    return True


def extract_nodes_from_text(text):
    """Извлекает реальные прокси-ссылки из полной Base64-подписки, обычного текста или смешанного вида."""
    if not text or not text.strip():
        return [], 0

    clean_text = text.lstrip("\ufeff").strip()
    nodes = []
    seen = set()
    total_found_any = 0

    def add_if_valid(candidate):
        nonlocal total_found_any
        raw_uri = candidate.lstrip("\ufeff").strip()
        if is_proxy_uri(raw_uri):
            total_found_any += 1
            if raw_uri not in seen:
                seen.add(raw_uri)
                nodes.append(raw_uri)
            return True
        return False

    decoded_whole = decode_base64_safe(clean_text)
    if decoded_whole:
        for line in decoded_whole.splitlines():
            add_if_valid(line)
        if total_found_any > 0:
            return nodes, total_found_any

    for line in clean_text.splitlines():
        s = line.strip()
        if not s or s.startswith(("#", "//", "<")):
            continue
        if not add_if_valid(s):
            decoded_line = decode_base64_safe(s)
            if decoded_line:
                for sub_line in decoded_line.splitlines():
                    add_if_valid(sub_line)

    return nodes, total_found_any
def load_existing_final():
    """Загружает существующие рабочие серверы из final.txt в их оригинальном виде."""
    existing = {}
    if os.path.exists(FINAL_FILE):
        with open(FINAL_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                uri = line.lstrip("\ufeff").strip()
                if is_proxy_uri(uri) and uri not in existing:
                    existing[uri] = 1
    return existing


def save_final_pool(records):
    """Сохраняет объединенный список серверов в final.txt до MAX_WORKING без правки строк."""
    items = [(ping, uri) for uri, ping in records.items()]
    items.sort(key=operator.itemgetter(0))
    selected = items[:MAX_WORKING]

    with open(FINAL_FILE, "w", encoding="utf-8") as f:
        for _, orig_uri in selected:
            f.write(f"{orig_uri}\n")

    return {uri: ping for ping, uri in selected}


def test_one_server_isolated(orig_uri, slot_id, encoded_test_url):
    """Использует фиксированные файлы слота внутри /tmp/mihomo_checker."""
    time.sleep(slot_id * 0.25)

    api_port = BASE_PORT + slot_id
    sub_path = os.path.join(WORK_TMP_DIR, f"sub_slot_{slot_id}.txt")
    cfg_path = os.path.join(WORK_TMP_DIR, f"cfg_slot_{slot_id}.yaml")

    proc = None
    try:
        with open(sub_path, "w", encoding="utf-8") as f:
            f.write(f"{orig_uri}\n")

        temp_config = {
            "external-controller": f"127.0.0.1:{api_port}",
            "log-level": "silent",
            "dns": {
                "enable": True,
                "ipv6": False,
                "nameserver": ["1.1.1.1", "8.8.8.8"]
            },
            "proxy-providers": {
                "test_prov": {
                    "type": "file",
                    "path": sub_path,
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
                    "use": ["test_prov"]
                }
            ]
        }

        with open(cfg_path, "w", encoding="utf-8") as f:
            yaml.dump(temp_config, f, allow_unicode=True)

        proc = subprocess.Popen(
            ["./mihomo", "-d", ".", "-f", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        api_ready = False
        for _ in range(12):
            time.sleep(0.35)
            if proc.poll() is not None:
                return orig_uri, 0, "MIHOMO_EXITED"
            try:
                ver_r = requests.get(f"{LOCAL_API_HOST}:{api_port}/version", timeout=2)
                if ver_r.status_code == 200:
                    api_ready = True
                    break
            except Exception:
                continue

        if not api_ready:
            return orig_uri, 0, "API_TIMEOUT"

        try:
            requests.put(f"{LOCAL_API_HOST}:{api_port}/providers/proxies/test_prov", timeout=3)
        except Exception:
            pass

        node_name = None
        for url_ep in (
            f"{LOCAL_API_HOST}:{api_port}/providers/proxies/test_prov",
            f"{LOCAL_API_HOST}:{api_port}/proxies"
        ):
            try:
                r_p = requests.get(url_ep, timeout=3)
                if r_p.status_code != 200:
                    continue
                payload = r_p.json().get("proxies", {})
                if isinstance(payload, list):
                    for item in payload:
                        if isinstance(item, dict) and item.get("name") and item.get("name") not in BUILTIN_PROXY_NAMES:
                            node_name = item.get("name")
                            break
                elif isinstance(payload, dict):
                    for k, item in payload.items():
                        if k not in BUILTIN_PROXY_NAMES and isinstance(item, dict) and item.get("type") not in (
                            "Selector", "URLTest", "Fallback", "LoadBalance", "Direct", "Reject", "Compatible", "Pass"
                        ):
                            node_name = k
                            break
                if node_name:
                    break
            except Exception:
                continue

        if not node_name:
            return orig_uri, 0, "NODE_NOT_PARSED"

        encoded_name = urllib.parse.quote(node_name, safe="")
        check_url = (
            f"{LOCAL_API_HOST}:{api_port}/proxies/{encoded_name}/delay"
            f"?timeout={DELAY_TIMEOUT_MS}&url={encoded_test_url}&expected=204"
        )
        r = requests.get(check_url, timeout=HTTP_DELAY_TIMEOUT_SEC)

        if r.status_code == 200:
            data = r.json()
            if "delay" in data:
                ping = int(data["delay"])
                if 0 < ping < MAX_PING:
                    return orig_uri, ping, "OK"
                return orig_uri, ping, f"HIGH_PING({ping})"
        return orig_uri, 0, f"HTTP_{r.status_code}"
    except Exception as e:
        return orig_uri, 0, f"ERR:{e}"
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()


def test_nodes_individually(nodes_to_test, existing_records, test_url, pass_label):
    """Тестирует кандидатов и сразу сохраняет в final.txt каждые 5 найденных рабочих серверов."""
    if not nodes_to_test:
        return existing_records, 0

    encoded_test_url = urllib.parse.quote(test_url, safe="")
    added_count = 0
    unflushed_count = 0
    fail_samples = 0

    for start_idx in range(0, len(nodes_to_test), MAX_WORKERS):
        if len(existing_records) >= MAX_WORKING:
            break

        wave = nodes_to_test[start_idx:start_idx + MAX_WORKERS]
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [
                executor.submit(test_one_server_isolated, orig_uri, slot, encoded_test_url)
                for slot, orig_uri in enumerate(wave)
            ]
            for future in as_completed(futures):
                orig_uri, ping, status = future.result()
                if status == "OK" and orig_uri not in existing_records:
                    existing_records[orig_uri] = ping
                    added_count += 1
                    unflushed_count += 1
                    log_debug(f"[{pass_label} OK {ping}ms] ({len(existing_records)}/{MAX_WORKING}) {orig_uri[:55]}")

                    if unflushed_count >= FLUSH_BATCH_SIZE:
                        existing_records = save_final_pool(existing_records)
                        unflushed_count = 0
                        log_debug(f"[{pass_label}] Сохранено в {FINAL_FILE}: {len(existing_records)}/{MAX_WORKING}")
                elif status != "OK" and fail_samples < 3:
                    fail_samples += 1
                    log_debug(f"[{pass_label} FAIL: {status}] {orig_uri[:45]}")

        if len(existing_records) < MAX_WORKING and (start_idx + MAX_WORKERS) < len(nodes_to_test):
            time.sleep(WAVE_COOLDOWN_SEC)

    if unflushed_count > 0:
        existing_records = save_final_pool(existing_records)
        log_debug(f"[{pass_label}] Сохранен остаток в {FINAL_FILE}: {len(existing_records)}/{MAX_WORKING}")

    return existing_records, added_count
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
    """Возвращает (is_permanently_bad, current_bad_days, clean_line_without_bad)."""
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
    """Выполняет один полный проход по списку подписок с заданным test_url."""
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

        batch_nodes = []
        total_found_any = 0
        download_ok = False
        try:
            resp = requests.get(fetch_url, timeout=SUB_DOWNLOAD_TIMEOUT_SEC)
            if resp.status_code == 200:
                download_ok = True
                batch_nodes, total_found_any = extract_nodes_from_text(resp.text)
                log_debug(f"[{pass_label}] Найдено серверов в подписке: {total_found_any}")
            else:
                log_debug(f"[{pass_label}] Ошибка HTTP {resp.status_code} для {orig_url[:50]}")
        except Exception as e:
            log_debug(f"[{pass_label}] Ошибка скачивания {orig_url[:50]}: {e}")

        added_from_sub = 0
        if download_ok and batch_nodes:
            new_candidates = [u for u in batch_nodes if u not in records]
            if new_candidates:
                records, added_from_sub = test_nodes_individually(
                    new_candidates, records, test_url, pass_label
                )

        ending = "\n" if raw_line.endswith("\n") else ""

        if download_ok and total_found_any > 0:
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
    # Сразу при старте очищаем /tmp/mihomo_checker и любые оставшиеся временные файлы
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
