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

MAX_PING = 300
MAX_WORKING = 30
BATCH_SIZE = 1
MAX_WORKERS = 15
BASE_PORT = 9100
MAX_RUNTIME_SECONDS = 2700

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

def extract_host(uri):
    try:
        if uri.startswith("vmess://"):
            body = uri.replace("vmess://", "", 1)
            raw_b64, _, _ = body.rpartition("#") if "#" in body else (body, "", "")
            d = json.loads(decode_base64_safe(raw_b64))
            return str(d.get("add", "")).strip()
        else:
            clean_uri, _, _ = uri.rpartition("#") if "#" in uri else (uri, "", "")
            parsed = urllib.parse.urlparse(clean_uri)
            return str(parsed.hostname or "").strip()
    except Exception:
        return ""

def is_valid_basic_uri(uri):
    if not any(uri.startswith(p) for p in PROTOCOLS):
        return False
    host = extract_host(uri)
    return bool(host and ("." in host or ":" in host))

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

def load_tested_records():
    records = {}
    if os.path.exists("tested.txt"):
        with open("tested.txt", "r", encoding="utf-8") as f:
            for line in f:
                ping_str, sep, orig_uri = line.strip().partition(" ")
                if sep and ping_str.isdigit():
                    records[orig_uri] = int(ping_str)
    return records

def save_results(records, dns_cache=None, networks_by_code=None):
    priority_order = [c.upper() for c in ALLOWED_COUNTRY_CODES]
    enriched = []
    for orig_uri, ping in records.items():
        if ping >= MAX_PING:
            continue
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

    with open("tested.txt", "w", encoding="utf-8") as f:
        for _, ping, orig_uri, _ in selected:
            f.write(f"{ping:03d} {orig_uri}\n")

    with open("final.txt", "w", encoding="utf-8") as f:
        for idx, (_, _, orig_uri, c_up) in enumerate(selected, start=1):
            clean = build_named_uri(orig_uri, idx, c_up)
            f.write(f"{clean}\n")

    return {uri: ping for _, ping, uri, _ in selected}
def test_one_server_isolated(orig_uri, slot_id, encoded_test_url):
    """Тестирует оригинальную ссылку 1-в-1 через провайдер Mihomo (в Base64) без изменения параметров."""
    if orig_uri.startswith("vmess://"):
        test_uri = orig_uri
    else:
        base, _, _ = orig_uri.rpartition("#") if "#" in orig_uri else (orig_uri, "", "")
        test_uri = f"{base}#single_node"

    b64_sub = base64.b64encode((test_uri + "\n").encode("utf-8")).decode("utf-8")
    api_port = BASE_PORT + slot_id

    fd_sub, sub_path = tempfile.mkstemp(prefix=f"sub_{slot_id}_", suffix=".txt", dir=".")
    os.close(fd_sub)
    fd_cfg, cfg_path = tempfile.mkstemp(prefix=f"mihomo_{slot_id}_", suffix=".yaml", dir=".")
    os.close(fd_cfg)

    proc = None
    try:
        with open(sub_path, "w", encoding="utf-8") as f:
            f.write(b64_sub)

        temp_config = {
            "external-controller": f"127.0.0.1:{api_port}",
            "dns": {
                "enable": True,
                "ipv6": False,
                "nameserver": ["1.1.1.1", "8.8.8.8"]
            },
            "proxy-providers": {
                "pool": {
                    "type": "file",
                    "path": os.path.abspath(sub_path)
                }
            },
            "proxy-groups": [
                {
                    "name": "AUTO",
                    "type": "select",
                    "use": ["pool"]
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
        time.sleep(1.2)

        if proc.poll() is not None:
            return orig_uri, 0, "MIHOMO_CRASH"

        r_list = requests.get(f"{LOCAL_API_HOST}:{api_port}/proxies", timeout=3)
        if r_list.status_code != 200:
            return orig_uri, 0, "API_ERR"

        proxies_dict = r_list.json().get("proxies", {})
        target_name = None
        for pname in proxies_dict.keys():
            if pname not in ("DIRECT", "REJECT", "GLOBAL", "AUTO", "COMPATIBLE", "PASS"):
                target_name = pname
                break

        if not target_name:
            return orig_uri, 0, "PARSE_SKIPPED"

        enc_name = urllib.parse.quote(target_name, safe="")
        check_url = f"{LOCAL_API_HOST}:{api_port}/proxies/{enc_name}/delay?timeout=3500&url={encoded_test_url}&expected=204"
        r = requests.get(check_url, timeout=4.5)
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
def test_nodes_individually(nodes_to_test, existing_records, dns_cache=None, networks_by_code=None):
    if not nodes_to_test:
        return existing_records

    encoded_test_url = urllib.parse.quote(TEST_URL, safe="")
    sample_logged = 0

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
                    if orig_uri not in existing_records or ping < existing_records[orig_uri]:
                        existing_records[orig_uri] = ping
                    log_debug(f"[OK {ping}ms] ({len(existing_records)}/{MAX_WORKING}) {orig_uri[:55]}")
                elif sample_logged < 5:
                    log_debug(f"[ОТБРОШЕН: {status}] {orig_uri[:55]}")
                    sample_logged += 1

        if existing_records:
            existing_records = save_results(existing_records, dns_cache, networks_by_code)

    return existing_records

def has_unprocessed_lines(lines):
    for line in lines:
        s = line.strip()
        if s and not s.startswith("#"):
            return True
    return False

def main():
    with open("debug_log.txt", "w", encoding="utf-8") as f:
        f.write("=== СТАРТ ИНДИВИДУАЛЬНОЙ ПРОВЕРКИ ===\n")

    start_time = time.time()
    if not os.path.exists("test.txt"):
        log_debug("Файл test.txt не найден.")
        set_github_output("has_more", "false")
        return

    with open("test.txt", "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    if not has_unprocessed_lines(lines):
        log_debug("В test.txt нет новых ссылок для обработки.")
        set_github_output("has_more", "false")
        return

    networks_by_code = load_country_networks()
    dns_cache = {}
    tested_records = load_tested_records()

    if tested_records:
        log_debug(f"Перепроверка {len(tested_records)} существующих серверов...")
        rechecked = test_nodes_individually(list(tested_records.keys()), {}, dns_cache, networks_by_code)
        tested_records = save_results(rechecked, dns_cache, networks_by_code)

    while has_unprocessed_lines(lines):
        if time.time() - start_time > MAX_RUNTIME_SECONDS:
            log_debug("Достигнут лимит времени работы (45 мин). Сохраняем прогресс.")
            break

        if len(tested_records) >= MAX_WORKING:
            log_debug(f"Набрано {MAX_WORKING} рабочих серверов. Очищаем очередь.")
            lines = [l for l in lines if not l.strip() or l.strip().startswith("#")]
            with open("test.txt", "w", encoding="utf-8") as f:
                f.writelines(lines)
            break

        batch_nodes = set()
        new_lines = []
        processed_in_batch = 0

        for raw_line in lines:
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                new_lines.append(raw_line)
                continue

            if processed_in_batch >= BATCH_SIZE:
                new_lines.append(raw_line)
                continue

            processed_in_batch += 1
            log_debug(f"Обработка строки: {stripped[:65]}")

            if is_valid_basic_uri(stripped) and not is_excluded_by_text(stripped):
                batch_nodes.add(stripped)
                continue

            url_match = re.search(r"https?://[^\s]+", stripped)
            if url_match:
                url = url_match.group(0)
                try:
                    resp = requests.get(url, timeout=10)
                    if resp.status_code == 200:
                        extracted = extract_nodes_from_text(resp.text)
                        log_debug(f"Извлечено валидных URI: {len(extracted)}")
                        batch_nodes.update(extracted)
                except Exception as e:
                    log_debug(f"Ошибка скачивания {url[:45]}: {e}")

        unique_geo_nodes = filter_and_sort_by_priority(list(set(batch_nodes)), networks_by_code, dns_cache)
        log_debug(f"После фильтра стран (DE->NL->FR->GB->US) осталось: {len(unique_geo_nodes)}")

        with open("testing.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(unique_geo_nodes) + ("\n" if unique_geo_nodes else ""))

        if unique_geo_nodes:
            new_candidates = [u for u in unique_geo_nodes if u not in tested_records]
            tested_records = test_nodes_individually(new_candidates, tested_records, dns_cache, networks_by_code)
            tested_records = save_results(tested_records, dns_cache, networks_by_code)

        lines = new_lines
        with open("test.txt", "w", encoding="utf-8") as f:
            f.writelines(lines)
        log_debug(f"Строка завершена. Итого рабочих: {len(tested_records)}/{MAX_WORKING}")

    if os.path.exists("fail_counts.json"):
        os.remove("fail_counts.json")

    if has_unprocessed_lines(lines):
        set_github_output("has_more", "true")
    else:
        set_github_output("has_more", "false")

if __name__ == "__main__":
    main()
