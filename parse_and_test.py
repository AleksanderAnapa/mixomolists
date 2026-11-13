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
URL_HOST = "cp.cloudflare.com"
URL_PATH = "/generate_204"
TEST_URL = URL_SCHEME + URL_HOST + URL_PATH
EXPECTED_STATUS = 204
MIHOMO_API = "http://127.0.0.1:9090"

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

def is_valid_uri(uri):
    try:
        if uri.startswith("vmess://"):
            raw_b64 = uri.replace("vmess://", "", 1)
            b64_part, _, _ = raw_b64.partition("#")
            data = json.loads(decode_base64_safe(b64_part))
            if not data.get("add") or not data.get("port") or not data.get("id"):
                return False
            scy = str(data.get("scy", "auto")).lower()
            if scy in ("null", "none", ""):
                data["scy"] = "auto"
            return True
        else:
            parsed = urllib.parse.urlparse(uri)
            return bool(parsed.hostname and parsed.port and parsed.username)
    except Exception:
        return False

def extract_nodes_from_text(text):
    nodes = set()
    for line in text.splitlines():
        line = line.strip()
        if any(line.startswith(proto) for proto in PROTOCOLS) and is_valid_uri(line):
            nodes.add(line)
    
    if not nodes:
        decoded = decode_base64_safe(text)
        for line in decoded.splitlines():
            line = line.strip()
            if any(line.startswith(proto) for proto in PROTOCOLS) and is_valid_uri(line):
                nodes.add(line)

    if not nodes and "proxies:" in text:
        try:
            data = yaml.safe_load(text)
            if isinstance(data, dict) and isinstance(data.get("proxies"), list):
                for p in data["proxies"]:
                    uri = clash_proxy_to_uri(p)
                    if uri and is_valid_uri(uri):
                        nodes.add(uri)
        except Exception:
            pass
    return nodes

def extract_host(uri):
    try:
        if uri.startswith("vmess://"):
            raw_b64 = uri.replace("vmess://", "", 1)
            b64_part, _, _ = raw_b64.partition("#")
            data = json.loads(decode_base64_safe(b64_part))
            return str(data.get("add", "")).strip()
        else:
            parsed = urllib.parse.urlparse(uri)
            return parsed.hostname or ""
    except Exception:
        return ""

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
        except Exception:
            pass
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

def make_temp_uri(original_uri, temp_name):
    if original_uri.startswith("vmess://"):
        try:
            raw_b64 = original_uri.replace("vmess://", "", 1)
            b64_part, _, _ = raw_b64.partition("#")
            data = json.loads(decode_base64_safe(b64_part))
            data["ps"] = temp_name
            if str(data.get("scy", "auto")).lower() in ("null", "none", ""):
                data["scy"] = "auto"
            new_b64 = base64.b64encode(json.dumps(data, ensure_ascii=False).encode("utf-8")).decode("utf-8")
            return f"vmess://{new_b64}"
        except Exception:
            return None
    base_uri, _, _ = original_uri.partition("#")
    return f"{base_uri}#{temp_name}"
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
    check_url = f"{MIHOMO_API}/proxies/{t_name}/delay?timeout=4000&url={encoded_test_url}&expected={EXPECTED_STATUS}"
    try:
        r = requests.get(check_url, timeout=5)
        if r.status_code == 200 and "delay" in r.json():
            ping = int(r.json()["delay"])
            if 0 < ping < MAX_PING:
                return orig_uri, ping
    except Exception:
        pass
    return None

def run_mihomo_batch(chunk, existing_records, encoded_test_url):
    temp_map = {}
    temp_uris = []
    for idx, orig_uri in enumerate(chunk):
        t_name = f"node_{idx}"
        t_uri = make_temp_uri(orig_uri, t_name)
        if t_uri:
            temp_map[t_name] = orig_uri
            temp_uris.append(t_uri)

    if not temp_uris:
        return existing_records, True

    with open("temp_sub.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(temp_uris) + "\n")

    abs_sub_path = os.path.abspath("temp_sub.txt")
    temp_config = {
        "external-controller": "127.0.0.1:9090",
        "proxy-providers": {
            "test_pool": {
                "type": "file",
                "path": abs_sub_path
            }
        },
        "proxy-groups": [
            {
                "name": "AUTO",
                "type": "select",
                "use": ["test_pool"]
            }
        ]
    }
    with open("temp_mihomo.yaml", "w", encoding="utf-8") as f:
        yaml.dump(temp_config, f)

    mihomo_proc = subprocess.Popen(["./mihomo", "-d", ".", "-f", "temp_mihomo.yaml"])
    time.sleep(2.5)

    provider_ok = False
    try:
        r_debug = requests.get(f"{MIHOMO_API}/proxies/node_0", timeout=3)
        if r_debug.status_code == 200:
            provider_ok = True
    except Exception:
        pass

    if provider_ok:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [
                executor.submit(check_single_proxy, t_name, orig_uri, encoded_test_url)
                for t_name, orig_uri in temp_map.items()
            ]
            for future in as_completed(futures):
                res = future.result()
                if res:
                    orig_uri, ping = res
                    if orig_uri not in existing_records or ping < existing_records[orig_uri]:
                        existing_records[orig_uri] = ping

    mihomo_proc.terminate()
    mihomo_proc.wait()
    return existing_records, provider_ok

def test_nodes_with_mihomo(nodes_to_test, existing_records):
    if not nodes_to_test:
        return existing_records

    encoded_test_url = urllib.parse.quote(TEST_URL, safe="")

    for start_idx in range(0, len(nodes_to_test), CHUNK_SIZE):
        if len(existing_records) >= MAX_WORKING:
            break

        chunk = nodes_to_test[start_idx:start_idx + CHUNK_SIZE]
        existing_records, ok = run_mihomo_batch(chunk, existing_records, encoded_test_url)

        # Если в пачке из 100 штук попалась 1 битая ссылка и Mihomo отклонил пачку — дробим по 10 штук
        if not ok and len(chunk) > 10:
            for sub_idx in range(0, len(chunk), 10):
                if len(existing_records) >= MAX_WORKING:
                    break
                sub_chunk = chunk[sub_idx:sub_idx + 10]
                existing_records, _ = run_mihomo_batch(sub_chunk, existing_records, encoded_test_url)

        if existing_records:
            existing_records = save_results(existing_records)
            print(f"Сохранено рабочих серверов: {len(existing_records)}/{MAX_WORKING}")

    return existing_records

def has_unprocessed_lines(lines):
    for line in lines:
        s = line.strip()
        if s and not s.startswith("#"):
            return True
    return False

def main():
    start_time = time.time()
    if not os.path.exists("test.txt"):
        print("Файл test.txt не найден.")
        set_github_output("has_more", "false")
        return

    with open("test.txt", "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    if not has_unprocessed_lines(lines):
        print("В test.txt нет новых ссылок для обработки.")
        set_github_output("has_more", "false")
        return

    networks = load_country_networks()
    dns_cache = {}
    tested_records = load_tested_records()

    if tested_records:
        print(f"Перепроверка {len(tested_records)} существующих серверов...")
        rechecked = test_nodes_with_mihomo(list(tested_records.keys()), {})
        tested_records = save_results(rechecked)

    while has_unprocessed_lines(lines):
        if time.time() - start_time > MAX_RUNTIME_SECONDS:
            print("Достигнут лимит времени работы (45 мин). Сохраняем прогресс.")
            break

        if len(tested_records) >= MAX_WORKING:
            print(f"Набрано {MAX_WORKING} рабочих серверов. Очищаем очередь.")
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

            if any(stripped.startswith(proto) for proto in PROTOCOLS) and is_valid_uri(stripped):
                batch_nodes.add(stripped)
                continue

            url_match = re.search(r"https?://[^\s]+", stripped)
            if url_match:
                url = url_match.group(0)
                try:
                    resp = requests.get(url, timeout=10)
                    if resp.status_code == 200:
                        extracted = extract_nodes_from_text(resp.text)
                        batch_nodes.update(extracted)
                except Exception:
                    pass

        geo_nodes = filter_by_country(list(batch_nodes), networks, dns_cache)
        unique_geo_nodes = sorted(list(set(geo_nodes)))

        with open("testing.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(unique_geo_nodes) + ("\n" if unique_geo_nodes else ""))

        if unique_geo_nodes:
            new_candidates = [u for u in unique_geo_nodes if u not in tested_records]
            tested_records = test_nodes_with_mihomo(new_candidates, tested_records)
            tested_records = save_results(tested_records)

        lines = new_lines
        with open("test.txt", "w", encoding="utf-8") as f:
            f.writelines(lines)
        print(f"Порция обработана. Рабочих серверов в базе: {len(tested_records)}/{MAX_WORKING}")

    if os.path.exists("fail_counts.json"):
        os.remove("fail_counts.json")

    if has_unprocessed_lines(lines):
        set_github_output("has_more", "true")
    else:
        set_github_output("has_more", "false")

if __name__ == "__main__":
    main()
