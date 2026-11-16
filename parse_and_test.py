import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import json
import operator
import os
import re
import socket
import subprocess
import tempfile
import time
import urllib.parse
import requests
import yaml

PROTOCOLS = ("vless://", "vmess://", "trojan://")
ALLOWED_COUNTRY_CODES = ("de", "nl", "fr", "gb", "us")
BLOCKED_COUNTRY_CODES = ("RU", "BY", "CN", "HK", "MO", "IR", "SY", "CU", "KP", "AF")
EXCLUDE_REGEX = re.compile(
    r"(🇷🇺|🇧🇾|🇨🇳|🇭🇰|🇲🇴|🇮🇷|🇸🇾|🇨🇺|🇰🇵|🇦🇫|Россия|Russia|\bRU\b|Беларусь|Belarus|\bBY\b|Китай|China|\bCN\b|Гонконг|Hong Kong|\bHK\b|Макао|Macao|\bMO\b|Иран|Iran|\bIR\b|Сирия|Syria|\bSY\b|Куба|Cuba|\bCU\b|Корея|Korea|\bKP\b|Афганистан|Afghanistan|\bAF\b)",
    re.IGNORECASE
)

MAX_PING = 2000
MAX_WORKING = 60
MAX_WORKERS = 15
BASE_PORT = 9100
MAX_RUNTIME_SECONDS = 2700

SUBSCRIBES_FILE = "subscribes.txt"
FINAL_FILE = "final.txt"
CURSOR_FILE = "sub_cursor.txt"

TEST_URL = base64.b64decode("aHR0cHM6Ly9jcC5jbG91ZGZsYXJlLmNvbS9nZW5lcmF0ZV8yMDQ=").decode("utf-8")
CIDR_BASE_URL = base64.b64decode("aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2lwdmVyc2UvcmlyLWlwL21hc3Rlci9jb3VudHJ5Lw==").decode("utf-8")
GEO_API_URL = base64.b64decode("aHR0cHM6Ly9pcHdoby5pcy8=").decode("utf-8")
LOCAL_API_HOST = base64.b64decode("aHR0cDovLzEyNy4wLjAuMQ==").decode("utf-8")

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
        cleaned = re.sub(r"\s+", "", data)
        missing_padding = len(cleaned) % 4
        if missing_padding:
            cleaned += "=" * (4 - missing_padding)
        return base64.b64decode(cleaned).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def uri_to_clash_dict(uri, temp_name):
    try:
        clean_uri = uri.replace("&amp;", "&")
        if clean_uri.startswith("vmess://"):
            body = clean_uri.replace("vmess://", "", 1)
            raw_b64, _, _ = body.rpartition("#") if "#" in body else (body, "", "")
            d = json.loads(decode_base64_safe(raw_b64))
            if not d.get("add") or not d.get("port") or not d.get("id"):
                return None
            net = str(d.get("net", "tcp")).strip().lower()
            tls = str(d.get("tls", "")).lower() in ("tls", "1", "true")
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
                "tls": tls,
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

        no_tag, _, _ = clean_uri.rpartition("#") if "#" in clean_uri else (clean_uri, "", "")
        parsed = urllib.parse.urlparse(no_tag)
        params = urllib.parse.parse_qs(parsed.query)
        def get_p(k, default=""):
            vals = params.get(k)
            return str(next(iter(vals))).strip() if vals else default

        if not (parsed.hostname and parsed.port and parsed.username):
            return None

        net = get_p("type", "tcp").lower()
        security = get_p("security", "none").lower()
        sni = get_p("sni") or get_p("peer") or str(parsed.hostname)

        if no_tag.startswith("vless://"):
            proxy = {
                "name": temp_name,
                "type": "vless",
                "server": str(parsed.hostname),
                "port": int(parsed.port),
                "uuid": str(parsed.username),
                "udp": True,
                "tls": security in ("tls", "reality"),
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
                proxy["reality-opts"] = {
                    "public-key": pbk,
                    "short-id": sid
                }
                proxy["client-fingerprint"] = get_p("fp", "chrome") or "chrome"
            if net == "ws":
                proxy["ws-opts"] = {
                    "path": get_p("path", "/") or "/",
                    "headers": {"Host": get_p("host", sni) or sni}
                }
            elif net == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": get_p("serviceName", "")}
            return proxy
        if no_tag.startswith("trojan://"):
            proxy = {
                "name": temp_name,
                "type": "trojan",
                "server": str(parsed.hostname),
                "port": int(parsed.port),
                "password": str(parsed.username),
                "udp": True,
                "sni": sni,
                "skip-cert-verify": True,
                "network": net
            }
            if net == "ws":
                proxy["ws-opts"] = {
                    "path": get_p("path", "/") or "/",
                    "headers": {"Host": get_p("host", sni) or sni}
                }
            elif net == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": get_p("serviceName", "")}
            return proxy
    except Exception:
        return None
    return None

def extract_host(uri):
    d = uri_to_clash_dict(uri, "test")
    return d["server"] if d else ""

def normalize_core_uri(uri):
    """Возвращает ссылку без хвоста после # для сравнения дубликатов."""
    if uri.startswith("vmess://"):
        return uri.strip()
    if "#" in uri:
        base, _, _ = uri.rpartition("#")
        return base.strip()
    return uri.strip()

def is_valid_basic_uri(uri):
    if not any(uri.startswith(p) for p in PROTOCOLS):
        return False
    return uri_to_clash_dict(uri, "test") is not None

def is_excluded_by_text(uri):
    decoded_tag = urllib.parse.unquote(uri)
    if uri.startswith("vmess://"):
        body = uri.replace("vmess://", "", 1)
        raw_b64, _, _ = body.rpartition("#") if "#" in body else (body, "", "")
        decoded_tag += " " + decode_base64_safe(raw_b64)
    return bool(EXCLUDE_REGEX.search(decoded_tag))

def extract_nodes_from_text(text):
    nodes = set()
    for line in text.splitlines():
        line = line.strip()
        if is_valid_basic_uri(line) and not is_excluded_by_text(line):
            nodes.add(line)

    if not nodes:
        decoded = decode_base64_safe(text)
        for line in decoded.splitlines():
            line = line.strip()
            if is_valid_basic_uri(line) and not is_excluded_by_text(line):
                nodes.add(line)
    return nodes

def load_country_networks():
    networks_by_code = {}
    total = 0
    for code in ALLOWED_COUNTRY_CODES:
        url = CIDR_BASE_URL + f"{code}/ipv4-aggregated.txt"
        nets = []
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        nets.append(ipaddress.ip_network(line))
        except Exception as e:
            log_debug(f"Ошибка загрузки подсетей {code}: {e}")
        networks_by_code[code.upper()] = nets
        total += len(nets)
    log_debug(f"Загружено CIDR-подсетей стран: {total}")
    return networks_by_code

def resolve_host_country(host, networks_by_code, use_api_fallback=False):
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(1.5)
    try:
        ip_str = socket.gethostbyname(host)
        ip_obj = ipaddress.ip_address(ip_str)
        for code in ALLOWED_COUNTRY_CODES:
            c_up = code.upper()
            if any(ip_obj in net for net in networks_by_code.get(c_up, ())):
                return host, c_up
        if use_api_fallback:
            r = requests.get(f"{GEO_API_URL}{ip_str}", timeout=4)
            if r.status_code == 200:
                cc = str(r.json().get("country_code", "")).upper()
                if len(cc) == 2:
                    return host, cc
        return host, None
    except Exception:
        return host, None
    finally:
        socket.setdefaulttimeout(old_timeout)

def filter_and_sort_by_priority(uris, networks_by_code, dns_cache):
    has_any_nets = any(len(v) > 0 for v in networks_by_code.values())
    if not has_any_nets:
        return uris

    hosts_to_resolve = set()
    uri_hosts = []
    for uri in uris:
        host = extract_host(uri)
        uri_hosts.append((uri, host))
        if host and host not in dns_cache:
            hosts_to_resolve.add(host)

    if hosts_to_resolve:
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = [executor.submit(resolve_host_country, h, networks_by_code, False) for h in hosts_to_resolve]
            for future in as_completed(futures):
                h, code = future.result()
                dns_cache[h] = code

    priority_order = [c.upper() for c in ALLOWED_COUNTRY_CODES]
    ordered_uris = []
    for target_cc in priority_order:
        for uri, host in uri_hosts:
            if host and dns_cache.get(host) == target_cc:
                ordered_uris.append(uri)
    return ordered_uris
def build_named_uri(orig_uri, idx, country_code="UN"):
    """Меняет ТОЛЬКО комментарий после последнего # с конца. Ничего до него не трогает."""
    tag = f"{idx:02d}_{country_code.upper()}"
    if orig_uri.startswith("vmess://"):
        return orig_uri
    if "#" in orig_uri:
        base, _, _ = orig_uri.rpartition("#")
        return f"{base}#{tag}"
    return f"{orig_uri}#{tag}"

def load_existing_final():
    """Загружает уже существующие рабочие серверы из final.txt без повторной отбраковки."""
    existing = {}
    if os.path.exists(FINAL_FILE):
        with open(FINAL_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                uri = line.strip()
                if uri and any(uri.startswith(p) for p in PROTOCOLS):
                    core = normalize_core_uri(uri)
                    if core not in existing:
                        # Сохраняем существующий сервер с базовым приоритетом 0 (чтобы он остался в топе)
                        existing[core] = (1, uri)
    return existing

def save_final_pool(records, dns_cache=None, networks_by_code=None):
    """Сохраняет объединенный список (существующие + новые) в final.txt до MAX_WORKING штук."""
    priority_order = [c.upper() for c in ALLOWED_COUNTRY_CODES]
    enriched = []
    for core, (ping, orig_uri) in records.items():
        host = extract_host(orig_uri)
        c_code = dns_cache.get(host) if dns_cache else None
        if not c_code and host:
            _, c_code = resolve_host_country(host, networks_by_code or {}, True)
            if dns_cache is not None and c_code:
                dns_cache[host] = c_code
        c_up = (c_code or "UN").upper()
        if c_up in BLOCKED_COUNTRY_CODES:
            continue
        prio_idx = priority_order.index(c_up) if c_up in priority_order else 999
        enriched.append((prio_idx, ping, orig_uri, c_up))

    enriched.sort(key=operator.itemgetter(0, 1))
    selected = enriched[:MAX_WORKING]

    with open(FINAL_FILE, "w", encoding="utf-8") as f:
        for idx, (_, _, orig_uri, c_up) in enumerate(selected, start=1):
            clean = build_named_uri(orig_uri, idx, c_up)
            f.write(f"{clean}\n")

    return {normalize_core_uri(uri): (ping, uri) for _, ping, uri, _ in selected}

def test_one_server_isolated(orig_uri, slot_id, encoded_test_url):
    p_dict = uri_to_clash_dict(orig_uri, "single_node")
    if not p_dict:
        return orig_uri, 0, "INVALID_FORMAT"

    api_port = BASE_PORT + slot_id
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

    fd, cfg_path = tempfile.mkstemp(prefix=f"mihomo_{slot_id}_", suffix=".yaml", dir=".")
    os.close(fd)
    proc = None
    try:
        with open(cfg_path, "w", encoding="utf-8") as f:
            yaml.dump(temp_config, f, allow_unicode=True)

        proc = subprocess.Popen(
            ["./mihomo", "-d", ".", "-f", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(0.8)

        if proc.poll() is not None:
            return orig_uri, 0, "MIHOMO_REJECTED_NODE"

        check_url = f"{LOCAL_API_HOST}:{api_port}/proxies/single_node/delay?timeout=4500&url={encoded_test_url}&expected=204"
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
def test_nodes_individually(nodes_to_test, existing_records, dns_cache=None, networks_by_code=None):
    """Тестирует кандидатов и добавляет рабочие к existing_records до MAX_WORKING. Возвращает (records, added_count)."""
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
                    core = normalize_core_uri(orig_uri)
                    if core not in existing_records:
                        existing_records[core] = (ping, orig_uri)
                        added_count += 1
                        log_debug(f"[OK {ping}ms] ({len(existing_records)}/{MAX_WORKING}) {orig_uri[:55]}")

        if added_count > 0:
            existing_records = save_final_pool(existing_records, dns_cache, networks_by_code)

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

def normalize_github_url(url):
    """Превращает ссылки ://github.com... в прямые raw-ссылки."""
    if "github.com/" in url and "/blob/" in url:
        return url.replace("github.com/", "://githubusercontent.com").replace("/blob/", "/")
    return url

def main():
    with open("debug_log.txt", "w", encoding="utf-8") as f:
        f.write("=== СТАРТ ПОПОЛНЕНИЯ FINAL.TXT ===\n")

    start_time = time.time()
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

    total_lines = len(sub_lines)
    if total_lines == 0:
        set_github_output("has_more", "false")
        return

    # Проверяем, есть ли вообще активные (не BAD! и не #) подписки
    active_indices = [
        i for i, l in enumerate(sub_lines)
        if l.strip() and not l.strip().startswith("#") and not l.strip().upper().startswith("BAD!")
    ]
    if not active_indices:
        log_debug("В subscribes.txt не осталось рабочих подписок (все помечены BAD!).")
        set_github_output("has_more", "false")
        return

    networks_by_code = load_country_networks()
    dns_cache = {}
    records = save_final_pool(records, dns_cache, networks_by_code)

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

        # Пропускаем пустые строки, комментарии и уже помеченные BAD!
        if not stripped or stripped.startswith("#") or stripped.upper().startswith("BAD!"):
            write_cursor(cursor)
            continue

        url_match = re.search(r"https?://[^\s]+", stripped)
        if not url_match:
            write_cursor(cursor)
            continue

        orig_url = url_match.group(0)
        fetch_url = normalize_github_url(orig_url)
        log_debug(f"Проверка подписки [{idx + 1}/{total_lines}]: {orig_url[:65]}")

        batch_nodes = set()
        download_ok = False
        try:
            resp = requests.get(fetch_url, timeout=12)
            if resp.status_code == 200:
                download_ok = True
                batch_nodes = extract_nodes_from_text(resp.text)
                log_debug(f"Извлечено валидных URI: {len(batch_nodes)}")
            else:
                log_debug(f"Ошибка HTTP {resp.status_code} для {orig_url[:50]}")
        except Exception as e:
            log_debug(f"Ошибка скачивания {orig_url[:50]}: {e}")

        added_from_sub = 0
        if download_ok and batch_nodes:
            geo_nodes = filter_and_sort_by_priority(list(batch_nodes), networks_by_code, dns_cache)
            log_debug(f"После фильтра стран (DE->NL->FR->GB->US) осталось: {len(geo_nodes)}")
            new_candidates = [u for u in geo_nodes if normalize_core_uri(u) not in records]
            if new_candidates:
                records, added_from_sub = test_nodes_individually(new_candidates, records, dns_cache, networks_by_code)

        # Если подписка не загрузилась или дала 0 рабочих серверов -> помечаем BAD!
        if not download_ok or added_from_sub == 0:
            log_debug(f"Помечаем как BAD!: {orig_url[:65]}")
            ending = "\n" if raw_line.endswith("\n") else ""
            sub_lines[idx] = f"BAD! {stripped}{ending}"
            with open(SUBSCRIBES_FILE, "w", encoding="utf-8") as f:
                f.writelines(sub_lines)
        else:
            log_debug(f"Подписка рабочая (+{added_from_sub} серверов). Всего в final.txt: {len(records)}/{MAX_WORKING}")

        write_cursor(cursor)

    # Удаляем устаревшие файлы, если они оставались в репозитории
    for old_f in ("tested.txt", "testing.txt", "test.txt", "fail_counts.json"):
        if os.path.exists(old_f):
            os.remove(old_f)

    # Перезапуск только если не добрали до 60 из-за таймаута 45 мин и еще есть активные подписки
    still_active = any(
        l.strip() and not l.strip().startswith("#") and not l.strip().upper().startswith("BAD!")
        for l in sub_lines
    )
    if timed_out and len(records) < MAX_WORKING and still_active:
        set_github_output("has_more", "true")
    else:
        set_github_output("has_more", "false")

if __name__ == "__main__":
    main()
