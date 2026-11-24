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

# Безопасные тайминги и лимиты для перегруженных серверов
MAX_PING = 3500
MAX_WORKING = 20
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

NON_PROXY_SCHEMES = (
    "http://", "https://", "file://", "ftp://", "ftps://",
    "mailto:", "tg://", "javascript:", "data:", "ws://", "wss://", "happ://",
    "ss://", "ssr://", "wg://", "wireguard://"
)


def cleanup_temp_artifacts(recreate=True):
    """При старте и при выходе зачищает /tmp/mihomo_checker и любые старые хвосты."""
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


def is_proxy_uri(line):
    """Простая проверка без привязки к пробелам и спецсимволам в названиях после #."""
    if not line or "://" not in line:
        return False
    if line.startswith(("#", "//", "<", "{", "[", ";", "!")):
        return False
    lower = line.lower()
    if lower.startswith(NON_PROXY_SCHEMES):
        return False
    scheme, _, _ = line.partition("://")
    return bool(scheme) and scheme.replace("+", "").replace("-", "").replace(".", "").isalnum()


def extract_nodes_from_text(text):
    """Извлекает исходные URI-строки из полной Base64-подписки или обычного текста без правки строк."""
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

    if "://" not in clean_text:
        decoded_whole = decode_base64_safe(clean_text)
        if decoded_whole and "://" in decoded_whole:
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
            if decoded_line and "://" in decoded_line:
                for sub_line in decoded_line.splitlines():
                    add_if_valid(sub_line)

    return nodes, total_found_any
def apply_transport_opts(proxy, net, get_p, sni):
    if net == "ws":
        proxy["ws-opts"] = {
            "path": get_p("path", "/") or "/",
            "headers": {"Host": get_p("host", sni) or sni}
        }
    elif net == "grpc":
        proxy["grpc-opts"] = {"grpc-service-name": get_p("serviceName", "")}
    elif net == "httpupgrade":
        proxy["network"] = "ws"
        proxy["ws-opts"] = {
            "path": get_p("path", "/") or "/",
            "headers": {"Host": get_p("host", sni) or sni},
            "v2ray-http-upgrade": True
        }


def uri_to_clash_dict(uri, temp_name):
    """Создает временный dict только для современных протоколов с шифрованием/маскировкой."""
    try:
        clean_uri = uri.replace("&amp;", "&").strip()
        no_tag, _, _ = clean_uri.rpartition("#") if "#" in clean_uri else (clean_uri, "", "")
        scheme_match = re.match(r"^([a-zA-Z0-9+.-]+)://(.*)$", no_tag)
        if not scheme_match:
            return None

        scheme = scheme_match.group(1).lower()
        rest = scheme_match.group(2)

        if scheme == "vmess":
            d = json.loads(decode_base64_safe(rest))
            if not d.get("add") or not d.get("port") or not d.get("id"):
                return None
            tls = str(d.get("tls", "")).lower() in ("tls", "1", "true")
            if not tls:
                return None
            net = str(d.get("net", "tcp")).strip().lower()
            scy = str(d.get("scy", "auto")).strip().lower()
            if scy in ("null", "none", ""):
                scy = "auto"
            proxy = {
                "name": temp_name,
                "type": "vmess",
                "server": str(d["add"]).strip(),
                "port": int(d["port"]),
                "uuid": str(d["id"]).strip(),
                "alterId": int(d.get("aid", 0)),
                "cipher": scy,
                "udp": True,
                "tls": True,
                "skip-cert-verify": True,
                "network": net
            }
            if d.get("sni"):
                proxy["servername"] = str(d["sni"]).strip()
            elif d.get("host"):
                proxy["servername"] = str(d["host"]).strip()
            if net == "ws":
                proxy["ws-opts"] = {
                    "path": str(d.get("path", "/")).strip() or "/",
                    "headers": {"Host": str(d.get("host", d["add"])).strip()}
                }
            elif net == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": str(d.get("path", "")).strip()}
            return proxy

        parsed = urllib.parse.urlparse(no_tag)
        params = urllib.parse.parse_qs(parsed.query)

        def get_p(k, default=""):
            vals = params.get(k)
            return str(next(iter(vals))).strip() if vals else default

        if not (parsed.hostname and parsed.port):
            return None

        host = str(parsed.hostname)
        port = int(parsed.port)
        user = urllib.parse.unquote(parsed.username or "")
        pwd = urllib.parse.unquote(parsed.password or "")
        sni = get_p("sni") or get_p("peer") or host

        if scheme == "vless":
            if not user:
                return None
            net = get_p("type", "tcp").lower()
            security = get_p("security", "none").lower()
            if security not in ("tls", "reality"):
                return None
            proxy = {
                "name": temp_name,
                "type": "vless",
                "server": host,
                "port": port,
                "uuid": user,
                "udp": True,
                "tls": True,
                "skip-cert-verify": True,
                "servername": sni,
                "network": net
            }
            flow = get_p("flow")
            if flow:
                proxy["flow"] = flow
            if security == "reality":
                pbk = get_p("pbk")
                sid = get_p("sid", "")
                if not pbk:
                    return None
                if sid and (len(sid) > 16 or len(sid) % 2 != 0 or not re.fullmatch(r"[0-9a-fA-F]+", sid)):
                    return None
                proxy["reality-opts"] = {"public-key": pbk, "short-id": sid}
                proxy["client-fingerprint"] = get_p("fp", "chrome") or "chrome"
            apply_transport_opts(proxy, net, get_p, sni)
            return proxy

        if scheme == "trojan":
            if not user:
                return None
            net = get_p("type", "tcp").lower()
            proxy = {
                "name": temp_name,
                "type": "trojan",
                "server": host,
                "port": port,
                "password": user,
                "udp": True,
                "sni": sni,
                "skip-cert-verify": True,
                "network": net
            }
            apply_transport_opts(proxy, net, get_p, sni)
            return proxy

        if scheme in ("hy2", "hysteria2"):
            auth = f"{user}:{pwd}" if pwd else user
            if not auth:
                return None
            proxy = {
                "name": temp_name,
                "type": "hysteria2",
                "server": host,
                "port": port,
                "password": auth,
                "sni": sni,
                "skip-cert-verify": True
            }
            obfs = get_p("obfs")
            if obfs and obfs != "none":
                proxy["obfs"] = obfs
                if get_p("obfs-password"):
                    proxy["obfs-password"] = get_p("obfs-password")
            if get_p("mport"):
                proxy["ports"] = get_p("mport")
            return proxy

        if scheme == "hysteria":
            proxy = {
                "name": temp_name,
                "type": "hysteria",
                "server": host,
                "port": port,
                "auth-str": get_p("auth") or user,
                "up": get_p("upmbps", "50"),
                "down": get_p("downmbps", "100"),
                "protocol": get_p("protocol", "udp"),
                "sni": sni,
                "skip-cert-verify": True
            }
            if get_p("obfsParam"):
                proxy["obfs"] = get_p("obfsParam")
            if get_p("alpn"):
                proxy["alpn"] = [a.strip() for a in get_p("alpn").split(",") if a.strip()]
            return proxy

        if scheme == "tuic":
            if not (user and pwd):
                return None
            proxy = {
                "name": temp_name,
                "type": "tuic",
                "server": host,
                "port": port,
                "uuid": user,
                "password": pwd,
                "sni": sni,
                "skip-cert-verify": True,
                "congestion-controller": get_p("congestion_control", "bbr"),
                "udp-relay-mode": get_p("udp_relay_mode", "native")
            }
            if get_p("alpn"):
                proxy["alpn"] = [a.strip() for a in get_p("alpn").split(",") if a.strip()]
            return proxy

        if scheme == "anytls":
            if not user:
                return None
            return {
                "name": temp_name,
                "type": "anytls",
                "server": host,
                "port": port,
                "password": user,
                "sni": sni,
                "skip-cert-verify": True,
                "udp": True
            }
    except Exception:
        return None
    return None
def get_server_fingerprint(uri, parsed_dict=None):
    """Ключ дедупликации в памяти (type + server + port + uuid/password). Исходную строку не меняет."""
    d = parsed_dict if parsed_dict is not None else uri_to_clash_dict(uri, "fp")
    if d:
        cred = d.get("uuid") or d.get("password") or d.get("auth-str") or ""
        return f"{d.get('type')}|{str(d.get('server', '')).lower()}|{d.get('port')}|{cred}"
    return uri.strip()


def load_existing_final():
    """Загружает существующие серверы из final.txt в их оригинальном виде, отсекая дубли в памяти."""
    existing = {}
    if os.path.exists(FINAL_FILE):
        with open(FINAL_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                uri = line.lstrip("\ufeff").strip()
                if is_proxy_uri(uri) and uri_to_clash_dict(uri, "chk") is not None:
                    fp = get_server_fingerprint(uri)
                    if fp not in existing:
                        existing[fp] = (1, uri)
    return existing


def save_final_pool(records):
    """Сохраняет уникальные серверы в final.txt до MAX_WORKING в их оригинальном виде."""
    items = [(ping, orig_uri, fp) for fp, (ping, orig_uri) in records.items()]
    items.sort(key=operator.itemgetter(0))
    selected = items[:MAX_WORKING]

    with open(FINAL_FILE, "w", encoding="utf-8") as f:
        for _, orig_uri, _ in selected:
            f.write(f"{orig_uri}\n")

    return {fp: (ping, orig_uri) for ping, orig_uri, fp in selected}


def test_one_server_isolated(orig_uri, slot_id, encoded_test_url):
    """Проверенный способ запуска mihomo через proxies: [p_dict] в /tmp/mihomo_checker."""
    p_dict = uri_to_clash_dict(orig_uri, "single_node")
    if not p_dict:
        return orig_uri, 0, "FILTERED_OR_INVALID"

    time.sleep(slot_id * 0.25)

    api_port = BASE_PORT + slot_id
    cfg_path = os.path.join(WORK_TMP_DIR, f"cfg_slot_{slot_id}.yaml")
    temp_config = {
        "external-controller": f"127.0.0.1:{api_port}",
        "dns": {
            "enable": True,
            "ipv6": False,
            "nameserver": ["1.1.1.1", "8.8.8.8"]
        },
        "proxies": [p_dict],
        "proxy-groups": [
            {
                "name": "AUTO",
                "type": "select",
                "proxies": ["single_node"]
            }
        ]
    }

    proc = None
    try:
        with open(cfg_path, "w", encoding="utf-8") as f:
            yaml.dump(temp_config, f, allow_unicode=True)

        proc = subprocess.Popen(
            ["./mihomo", "-d", ".", "-f", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(1.2)

        if proc.poll() is not None:
            return orig_uri, 0, "MIHOMO_REJECTED_NODE"

        check_url = (
            f"{LOCAL_API_HOST}:{api_port}/proxies/single_node/delay"
            f"?timeout={DELAY_TIMEOUT_MS}&url={encoded_test_url}&expected=204"
        )
        r = requests.get(check_url, timeout=HTTP_DELAY_TIMEOUT_SEC)
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
                proc.wait(timeout=3)
            except Exception:
                proc.kill()


def test_nodes_individually(nodes_to_test, existing_records, test_url, pass_label):
    """Тестирует уникальных кандидатов и сохраняет в final.txt первую рабочую строку для каждого сервера."""
    if not nodes_to_test:
        return existing_records, 0

    encoded_test_url = urllib.parse.quote(test_url, safe="")
    added_count = 0
    unflushed_count = 0

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
                        unflushed_count += 1
                        log_debug(f"[{pass_label} OK {ping}ms] ({len(existing_records)}/{MAX_WORKING}) {orig_uri[:55]}")

                        if unflushed_count >= FLUSH_BATCH_SIZE:
                            existing_records = save_final_pool(existing_records)
                            unflushed_count = 0
                            log_debug(f"[{pass_label}] Сохранено в {FINAL_FILE}: {len(existing_records)}/{MAX_WORKING}")

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
        return url.replace("://github.com", "://raw.githubusercontent.com").replace("/blob/", "/")
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
            new_candidates = []
            for u in batch_nodes:
                p_d = uri_to_clash_dict(u, "chk")
                if p_d is not None:
                    fp = get_server_fingerprint(u, p_d)
                    if fp not in records:
                        new_candidates.append(u)
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
    cleanup_temp_artifacts(recreate=True)

    with open("debug_log.txt", "w", encoding="utf-8") as f:
        f.write("=== СТАРТ ПОПОЛНЕНИЯ FINAL.TXT ===\n")

    try:
        start_time = time.time()
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        records = load_existing_final()
        log_debug(f"В текущем {FINAL_FILE} уже есть уникальных серверов: {len(records)}/{MAX_WORKING}")

        if len(records) >= MAX_WORKING:
            log_debug("Список уже полон. Новые серверы не требуются.")
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
