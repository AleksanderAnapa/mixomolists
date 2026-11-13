import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import json
import operator
import os
import re
import socket
import subprocess
import time
import urllib.parse
import requests
import yaml

PROTOCOLS = ("vless://", "vmess://", "trojan://")
ALLOWED_COUNTRY_CODES = ("us", "de", "nl", "fr", "gb")
MAX_PING = 1000
MAX_WORKING = 30
BATCH_SIZE = 1
CHUNK_SIZE = 100
MAX_WORKERS = 20
MAX_RUNTIME_SECONDS = 2700

URL_SCHEME = "https://"
URL_HOST = "://cloudflare.com"
URL_PATH = "/generate_204"
TEST_URL = URL_SCHEME + URL_HOST + URL_PATH
MIHOMO_API = "http://127.0.0.1:9090"

def log_debug(msg):
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
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
        if uri.startswith("vmess://"):
            raw_b64 = uri.replace("vmess://", "", 1)
            b64_part, _, _ = raw_b64.partition("#")
            d = json.loads(decode_base64_safe(b64_part))
            if not d.get("add") or not d.get("port") or not d.get("id"):
                return None
            net = str(d.get("net", "tcp"))
            tls = str(d.get("tls", "")).lower() in ("tls", "1", "true")
            proxy = {
                "name": temp_name,
                "type": "vmess",
                "server": str(d["add"]).strip(),
                "port": int(d["port"]),
                "uuid": str(d["id"]).strip(),
                "alterId": int(d.get("aid", 0)),
                "cipher": "auto",
                "udp": True,
                "tls": tls,
                "skip-cert-verify": True,
                "network": net
            }
            if d.get("sni"):
                proxy["servername"] = str(d["sni"])
            elif d.get("host"):
                proxy["servername"] = str(d["host"])
            if net == "ws":
                proxy["ws-opts"] = {
                    "path": str(d.get("path", "/")),
                    "headers": {"Host": str(d.get("host", d["add"]))}
                }
            elif net == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": str(d.get("path", ""))}
            return proxy

        parsed = urllib.parse.urlparse(uri)
        params = urllib.parse.parse_qs(parsed.query)
        def get_p(k, default=""):
            vals = params.get(k)
            return str(next(iter(vals))) if vals else default

        if not (parsed.hostname and parsed.port and parsed.username):
            return None

        net = get_p("type", "tcp")
        security = get_p("security", "none")
        sni = get_p("sni") or get_p("peer") or str(parsed.hostname)

        if uri.startswith("vless://"):
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
                if not pbk:
                    return None
                proxy["reality-opts"] = {
                    "public-key": pbk,
                    "short-id": get_p("sid", "")
                }
                proxy["client-fingerprint"] = get_p("fp", "chrome")
            if net == "ws":
                proxy["ws-opts"] = {
                    "path": get_p("path", "/"),
                    "headers": {"Host": get_p("host", sni)}
                }
            elif net == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": get_p("serviceName", "")}
            return proxy
        if uri.startswith("trojan://"):
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
                    "path": get_p("path", "/"),
                    "headers": {"Host": get_p("host", sni)}
                }
            elif net == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": get_p("serviceName", "")}
            return proxy
    except Exception:
        return None
    return None

def clash_proxy_to_uri(p):
    ptype = p.get("type")
    if ptype not in ("vless", "vmess", "trojan"):
        return None
    name = urllib.parse.quote(str(p.get("name", "node")))
    server = p.get("server")
    port = p.get("port")
    if not (server and port):
        return None
    if ptype == "trojan":
        password = p.get("password", "")
        sni = p.get("sni", server)
        net = p.get("network", "tcp")
        return f"trojan://{password}@{server}:{port}?type={net}&sni={sni}#{name}"
    elif ptype == "vless":
        uuid = p.get("uuid", "")
        sni = p.get("servername", server)
        net = p.get("network", "tcp")
        tls = "tls" if p.get("tls") else "none"
        return f"vless://{uuid}@{server}:{port}?security={tls}&type={net}&sni={sni}#{name}"
    return None

def extract_nodes_from_text(text):
    nodes = set()
    for line in text.splitlines():
        line = line.strip()
        if any(line.startswith(proto) for proto in PROTOCOLS) and uri_to_clash_dict(line, "test"):
            nodes.add(line)
    
    if not nodes:
        decoded = decode_base64_safe(text)
        for line in decoded.splitlines():
            line = line.strip()
            if any(line.startswith(proto) for proto in PROTOCOLS) and uri_to_clash_dict(line, "test"):
                nodes.add(line)

    if not nodes and "proxies:" in text:
        try:
            data = yaml.safe_load(text)
            if isinstance(data, dict) and isinstance(data.get("proxies"), list):
                for p in data["proxies"]:
                    uri = clash_proxy_to_uri(p)
                    if uri and uri_to_clash_dict(uri, "test"):
                        nodes.add(uri)
        except Exception:
            pass
    return nodes

def extract_host(uri):
    d = uri_to_clash_dict(uri, "test")
    return d["server"] if d else ""

def load_country_networks():
    networks = []
    for code in ALLOWED_COUNTRY_CODES:
        url = f"https://githubusercontent.com{code}.cidr"
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        networks.append(ipaddress.ip_network(line))
        except Exception as e:
            log_debug(f"Ошибка загрузки подсетей {code}: {e}")
    log_debug(f"Загружено CIDR-подсетей стран: {len(networks)}")
    return networks

def filter_by_country(uris, networks, dns_cache):
    if not networks:
        return uris

    allowed_uris = []
    for uri in uris:
        host = extract_host(uri)
        if not host:
            continue
        if host not in dns_cache:
            try:
                ip_str = socket.gethostbyname(host)
                ip_obj = ipaddress.ip_address(ip_str)
                dns_cache[host] = any(ip_obj in net for net in networks)
            except Exception:
                dns_cache[host] = False
        if dns_cache[host]:
            allowed_uris.append(uri)
    return allowed_uris

def load_tested_records():
    records = {}
    if os.path.exists("tested.txt"):
        with open("tested.txt", "r", encoding="utf-8") as f:
            for line in f:
                ping_str, sep, orig_uri = line.strip().partition(" ")
                if sep and ping_str.isdigit():
                    records[orig_uri] = int(ping_str)
    return records
def save_results(records):
    sorted_items = sorted(records.items(), key=operator.itemgetter(1))[:MAX_WORKING]
    with open("tested.txt", "w", encoding="utf-8") as f:
        for orig_uri, ping in sorted_items:
            f.write(f"{ping:03d} {orig_uri}\n")
    with open("final.txt", "w", encoding="utf-8") as f:
        for orig_uri, _ in sorted_items:
            f.write(f"{orig_uri}\n")
    return dict(sorted_items)

def check_single_proxy(t_name, orig_uri, encoded_test_url):
    check_url = f"{MIHOMO_API}/proxies/{t_name}/delay?timeout=4000&url={encoded_test_url}"
    try:
        r = requests.get(check_url, timeout=5)
        if r.status_code == 200 and "delay" in r.json():
            ping = int(r.json()["delay"])
            if 0 < ping < MAX_PING:
                return orig_uri, ping, "OK"
            return orig_uri, ping, f"HIGH_PING({ping})"
        return orig_uri, 0, f"HTTP_{r.status_code}:{r.text[:60]}"
    except Exception as e:
        return orig_uri, 0, f"ERR:{e}"

def run_mihomo_batch(chunk, existing_records, encoded_test_url):
    temp_map = {}
    proxies_list = []
    for idx, orig_uri in enumerate(chunk):
        t_name = f"node_{idx}"
        p_dict = uri_to_clash_dict(orig_uri, t_name)
        if p_dict:
            temp_map[t_name] = orig_uri
            proxies_list.append(p_dict)

    log_debug(f"Конвертировано в YAML для Mihomo: {len(proxies_list)} из {len(chunk)} узлов.")
    if not proxies_list:
        return existing_records

    temp_config = {
        "external-controller": "127.0.0.1:9090",
        "dns": {
            "enable": True,
            "ipv6": False,
            "nameserver": ["1.1.1.1", "8.8.8.8"]
        },
        "proxies": proxies_list,
        "proxy-groups": [
            {
                "name": "AUTO",
                "type": "select",
                "proxies": list(temp_map.keys())
            }
        ]
    }
    with open("temp_mihomo.yaml", "w", encoding="utf-8") as f:
        yaml.dump(temp_config, f, allow_unicode=True)

    mihomo_proc = subprocess.Popen(["./mihomo", "-d", ".", "-f", "temp_mihomo.yaml"])
    time.sleep(2)

    sample_logged = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(check_single_proxy, t_name, orig_uri, encoded_test_url)
            for t_name, orig_uri in temp_map.items()
        ]
        for future in as_completed(futures):
            orig_uri, ping, status = future.result()
            if status == "OK":
                if orig_uri not in existing_records or ping < existing_records[orig_uri]:
                    existing_records[orig_uri] = ping
            elif sample_logged < 3:
                log_debug(f"Пример отказа узла: {status} | {orig_uri[:45]}")
                sample_logged += 1

    mihomo_proc.terminate()
    mihomo_proc.wait()
    return existing_records

def test_nodes_with_mihomo(nodes_to_test, existing_records):
    if not nodes_to_test:
        return existing_records

    encoded_test_url = urllib.parse.quote(TEST_URL, safe="")

    for start_idx in range(0, len(nodes_to_test), CHUNK_SIZE):
        if len(existing_records) >= MAX_WORKING:
            break

        chunk = nodes_to_test[start_idx:start_idx + CHUNK_SIZE]
        existing_records = run_mihomo_batch(chunk, existing_records, encoded_test_url)

        if existing_records:
            existing_records = save_results(existing_records)
            log_debug(f"Сохранено рабочих серверов: {len(existing_records)}/{MAX_WORKING}")

    return existing_records

def has_unprocessed_lines(lines):
    for line in lines:
        s = line.strip()
        if s and not s.startswith("#"):
            return True
    return False

def main():
    with open("debug_log.txt", "w", encoding="utf-8") as f:
        f.write("=== СТАРТ ПРОВЕРКИ ===\n")

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

    networks = load_country_networks()
    dns_cache = {}
    tested_records = load_tested_records()

    if tested_records:
        log_debug(f"Перепроверка {len(tested_records)} существующих серверов...")
        rechecked = test_nodes_with_mihomo(list(tested_records.keys()), {})
        tested_records = save_results(rechecked)

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
            log_debug(f"Обработка строки из test.txt: {stripped[:65]}")

            if any(stripped.startswith(proto) for proto in PROTOCOLS) and uri_to_clash_dict(stripped, "test"):
                batch_nodes.add(stripped)
                continue

            url_match = re.search(r"https?://[^\s]+", stripped)
            if url_match:
                url = url_match.group(0)
                try:
                    resp = requests.get(url, timeout=10)
                    log_debug(f"HTTP {resp.status_code} | Размер ответа: {len(resp.text)} байт")
                    if resp.status_code == 200:
                        extracted = extract_nodes_from_text(resp.text)
                        log_debug(f"Извлечено валидных URI: {len(extracted)}")
                        batch_nodes.update(extracted)
                except Exception as e:
                    log_debug(f"Ошибка скачивания {url[:45]}: {e}")

        geo_nodes = filter_by_country(list(batch_nodes), networks, dns_cache)
        unique_geo_nodes = sorted(list(set(geo_nodes)))
        log_debug(f"После фильтра стран осталось: {len(unique_geo_nodes)}")

        with open("testing.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(unique_geo_nodes) + ("\n" if unique_geo_nodes else ""))

        if unique_geo_nodes:
            new_candidates = [u for u in unique_geo_nodes if u not in tested_records]
            tested_records = test_nodes_with_mihomo(new_candidates, tested_records)
            tested_records = save_results(tested_records)

        lines = new_lines
        with open("test.txt", "w", encoding="utf-8") as f:
            f.writelines(lines)
        log_debug(f"Порция завершена. Итого рабочих: {len(tested_records)}/{MAX_WORKING}")

    if os.path.exists("fail_counts.json"):
        os.remove("fail_counts.json")

    if has_unprocessed_lines(lines):
        set_github_output("has_more", "true")
    else:
        set_github_output("has_more", "false")

if __name__ == "__main__":
    main()
