import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
import operator
import os
import re
import subprocess
import tempfile
import time
import urllib.parse
import requests
import yaml

MAX_PING = 2000
MAX_WORKING = 60
MAX_WORKERS = 15
BASE_PORT = 9100
MAX_RUNTIME_SECONDS = 2700
MAX_BAD_DAYS = 5

SUBSCRIBES_FILE = "subscribes.txt"
FINAL_FILE = "final.txt"
CURSOR_FILE = "sub_cursor.txt"
SUB_STATS_FILE = "sub_stats.json"

TEST_URL = base64.b64decode("aHR0cHM6Ly9jcC5jbG91ZGZsYXJlLmNvbS9nZW5lcmF0ZV8yMDQ=").decode("utf-8")
LOCAL_API_HOST = base64.b64decode("aHR0cDovLzEyNy4wLjAuMQ==").decode("utf-8")

URI_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://\S+")


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
        cleaned = re.sub(r"\s+", "", data).replace("-", "+").replace("_", "/")
        missing_padding = len(cleaned) % 4
        if missing_padding:
            cleaned += "=" * (4 - missing_padding)
        return base64.b64decode(cleaned).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def get_server_fingerprint(uri):
    """Уникальный отпечаток строки без тега после # для защиты от дубликатов (саму строку не меняет)."""
    s = uri.strip()
    if "#" in s and not s.lower().startswith("vmess://"):
        base, _, _ = s.rpartition("#")
        return base.strip()
    return s


def is_proxy_uri(line):
    """Проверяет, что строка является URI-ссылкой, отсекая обычные http/https сайты."""
    if not URI_SCHEME_RE.match(line):
        return False
    lower = line.lower()
    if lower.startswith(("http://", "https://", "file://", "ftp://", "mailto:", "tg://")):
        return False
    return True


def extract_nodes_from_text(text):
    """Извлекает исходные URI-строки из подписки без каких-либо изменений."""
    nodes = {}
    total_found_any = 0

    def process_lines(lines_iter):
        nonlocal total_found_any
        for line in lines_iter:
            line = line.strip()
            if is_proxy_uri(line):
                total_found_any += 1
                fp = get_server_fingerprint(line)
                if fp not in nodes:
                    nodes[fp] = line

    process_lines(text.splitlines())
    if total_found_any == 0:
        decoded = decode_base64_safe(text)
        process_lines(decoded.splitlines())

    return list(nodes.values()), total_found_any


def load_existing_final():
    """Загружает существующие рабочие серверы из final.txt в их оригинальном виде."""
    existing = {}
    if os.path.exists(FINAL_FILE):
        with open(FINAL_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                uri = line.strip()
                if uri and is_proxy_uri(uri):
                    fp = get_server_fingerprint(uri)
                    if fp not in existing:
                        existing[fp] = (1, uri)
    return existing


def save_final_pool(records):
    """Сохраняет объединенный список уникальных серверов в final.txt до MAX_WORKING без правки строк."""
    items = []
    seen_fps = set()

    for fp, (ping, orig_uri) in records.items():
        if fp in seen_fps:
            continue
        seen_fps.add(fp)
        items.append((ping, orig_uri, fp))

    items.sort(key=operator.itemgetter(0))
    selected = items[:MAX_WORKING]

    with open(FINAL_FILE, "w", encoding="utf-8") as f:
        for _, orig_uri, _ in selected:
            f.write(f"{orig_uri}\n")

    return {fp: (ping, uri) for ping, uri, fp in selected}
def test_one_server_isolated(orig_uri, slot_id, encoded_test_url):
    """Передает исходную строку напрямую в mihomo через proxy-providers. Сам mihomo разбирает протокол и мерит пинг."""
    api_port = BASE_PORT + slot_id

    fd_sub, sub_path = tempfile.mkstemp(prefix=f"sub_{slot_id}_", suffix=".txt", dir=".")
    os.close(fd_sub)

    fd_cfg, cfg_path = tempfile.mkstemp(prefix=f"mihomo_{slot_id}_", suffix=".yaml", dir=".")
    os.close(fd_cfg)

    proc = None
    try:
        with open(sub_path, "w", encoding="utf-8") as f:
            f.write(f"{orig_uri}\n")

        temp_config = {
            "external-controller": f"127.0.0.1:{api_port}",
            "dns": {
                "enable": True,
                "ipv6": False,
                "nameserver": ["1.1.1.1", "8.8.8.8"]
            },
            "proxy-providers": {
                "test_prov": {
                    "type": "file",
                    "path": f"./{os.path.basename(sub_path)}",
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
        time.sleep(0.8)

        if proc.poll() is not None:
            return orig_uri, 0, "MIHOMO_EXITED"

        prov_r = requests.get(f"{LOCAL_API_HOST}:{api_port}/providers/proxies/test_prov", timeout=4)
        if prov_r.status_code != 200:
            return orig_uri, 0, "PROVIDER_ERR"

        proxies = prov_r.json().get("proxies", [])
        if not proxies:
            return orig_uri, 0, "UNSUPPORTED_BY_MIHOMO"

        node_name = proxies[0].get("name")
        if not node_name:
            return orig_uri, 0, "NO_NAME"

        encoded_name = urllib.parse.quote(node_name, safe="")
        check_url = f"{LOCAL_API_HOST}:{api_port}/proxies/{encoded_name}/delay?timeout=4500&url={encoded_test_url}&expected=204"
        r = requests.get(check_url, timeout=5.5)

        if r.status_code == 200 and "delay" in r.json():
            ping = int(r.json()["delay"])
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
                proc.wait(timeout=2)
            except Exception:
                proc.kill()
        if os.path.exists(cfg_path):
            os.remove(cfg_path)
        if os.path.exists(sub_path):
            os.remove(sub_path)


def test_nodes_individually(nodes_to_test, existing_records):
    """Тестирует уникальных кандидатов и добавляет рабочие к existing_records до MAX_WORKING."""
    if not nodes_to_test:
        return existing_records, 0

    encoded_test_url = urllib.parse.quote(TEST_URL, safe="")
    added_count = 0

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
                if status == "OK":
                    fp = get_server_fingerprint(orig_uri)
                    if fp not in existing_records:
                        existing_records[fp] = (ping, orig_uri)
                        added_count += 1
                        log_debug(f"[OK {ping}ms] ({len(existing_records)}/{MAX_WORKING}) {orig_uri[:55]}")

        if added_count > 0:
            existing_records = save_final_pool(existing_records)

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


def normalize_github_url(url):
    if "://github.com" in url and "/blob/" in url:
        return url.replace("://github.com", "://://githubusercontent.com").replace("/blob/", "/")
    return url


def main():
    with open("debug_log.txt", "w", encoding="utf-8") as f:
        f.write("=== СТАРТ ПОПОЛНЕНИЯ FINAL.TXT ===\n")

    start_time = time.time()
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    records = load_existing_final()
    log_debug(f"В текущем {FINAL_FILE} уже есть уникальных серверов: {len(records)}/{MAX_WORKING}")

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

    total_lines = len(sub_lines)
    if total_lines == 0:
        set_github_output("has_more", "false")
        return

    active_indices = []
    for i, l in enumerate(sub_lines):
        s = l.strip()
        if not s or s.startswith("#"):
            continue
        perm_bad, _, _ = parse_sub_line(s)
        if not perm_bad:
            active_indices.append(i)

    if not active_indices:
        log_debug("В subscribes.txt не осталось рабочих подписок (все помечены BAD!_00).")
        set_github_output("has_more", "false")
        return

    sub_stats = load_sub_stats()
    records = save_final_pool(records)

    cursor = read_cursor()
    if cursor >= total_lines:
        cursor = 0

    checked_this_run = 0
    timed_out = False

    while len(records) < MAX_WORKING and checked_this_run < total_lines:
        if time.time() - start_time > MAX_RUNTIME_SECONDS:
            log_debug("Достигнут лимит времени работы (45 мин). Продолжим в следующем запуске.")
            timed_out = True
            break

        idx = cursor
        cursor = (cursor + 1) % total_lines
        checked_this_run += 1

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
        fetch_url = normalize_github_url(orig_url)
        log_debug(f"Проверка подписки [{idx + 1}/{total_lines}] (сбоев: {curr_days} дн.): {orig_url[:60]}")

        batch_nodes = []
        total_found_any = 0
        download_ok = False
        try:
            resp = requests.get(fetch_url, timeout=12)
            if resp.status_code == 200:
                download_ok = True
                batch_nodes, total_found_any = extract_nodes_from_text(resp.text)
                log_debug(f"Найдено серверов в подписке: {total_found_any}")
            else:
                log_debug(f"Ошибка HTTP {resp.status_code} для {orig_url[:50]}")
        except Exception as e:
            log_debug(f"Ошибка скачивания {orig_url[:50]}: {e}")

        added_from_sub = 0
        if download_ok and batch_nodes:
            new_candidates = [u for u in batch_nodes if get_server_fingerprint(u) not in records]
            if new_candidates:
                records, added_from_sub = test_nodes_individually(new_candidates, records)

        ending = "\n" if raw_line.endswith("\n") else ""

        if download_ok and total_found_any > 0:
            if curr_days > 0:
                log_debug(f"Подписка живая (найдено {total_found_any} серверов)! Снимаем метку BAD! с {orig_url[:55]}")
            else:
                log_debug(f"Подписка живая (+{added_from_sub} в пул). Всего в final.txt: {len(records)}/{MAX_WORKING}")
            sub_lines[idx] = f"{clean_line}{ending}"
            sub_stats.pop(orig_url, None)
        else:
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
                log_debug(f"Более {MAX_BAD_DAYS} дней сбоев (пусто/ошибка) -> постоянный бан BAD!_00: {orig_url[:55]}")
                sub_lines[idx] = f"BAD!_00 {clean_line}{ending}"
            else:
                tag = f"BAD!_{days:02d}"
                log_debug(f"Подписка пуста или недоступна -> {tag}: {orig_url[:55]}")
                sub_lines[idx] = f"{tag} {clean_line}{ending}"

        with open(SUBSCRIBES_FILE, "w", encoding="utf-8") as f:
            f.writelines(sub_lines)
        save_sub_stats(sub_stats)
        write_cursor(cursor)

    for old_f in ("tested.txt", "testing.txt", "test.txt", "fail_counts.json"):
        if os.path.exists(old_f):
            os.remove(old_f)

    still_active = any(
        l.strip() and not l.strip().startswith("#") and not parse_sub_line(l.strip())[0]
        for l in sub_lines
    )
    if timed_out and len(records) < MAX_WORKING and still_active:
        set_github_output("has_more", "true")
    else:
        set_github_output("has_more", "false")


if __name__ == "__main__":
    main()
