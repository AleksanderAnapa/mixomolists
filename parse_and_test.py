import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import json
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
MAX_PING = 200
MAX_WORKING = 30
BATCH_SIZE = 5               # Сколько строк из test.txt обрабатывать за один мини-цикл
MAX_WORKERS = 20             # Количество потоков для одновременной проверки серверов
MAX_RUNTIME_SECONDS = 2700   # 45 минут безопасной работы до перезапуска

TEST_URL = "https://cloudflare.com"
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

def extract_nodes_from_text(text):
    nodes = set()
    for line in text.splitlines():
        line = line.strip()
        if any(line.startswith(proto) for proto in PROTOCOLS):
            nodes.add(line)
    
    if not nodes:
        decoded = decode_base64_safe(text)
        for line in decoded.splitlines():
            line = line.strip()
            if any(line.startswith(proto) for proto in PROTOCOLS):
                nodes.add(line)

    if not nodes and "proxies:" in text:
        try:
            data = yaml.safe_load(text)
            if isinstance(data, dict) and isinstance(data.get("proxies"), list):
                for p in data["proxies"]:
                    uri = clash_proxy_to_uri(p)
                    if uri:
                        nodes.add(uri)
        except Exception:
            pass
    return nodes

def extract_host(uri):
    try:
        if uri.startswith("vmess://"):
            b64_part = uri[8:].split("#", 1)[0]
            decoded = decode_base64_safe(b64_part)
            data = json.loads(decoded)
            return data.get("add", "").strip()
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
        return original_uri
    base_uri = original_uri.split("#", 1)[0]
    return f"{base_uri}#{temp_name}"
def load_tested_records():
    records = {}
    if os.path.exists("tested.txt"):
        with open("tested.txt", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(" ", 1)
                if len(parts) == 2 and parts[0].isdigit():
                    records[parts[1]] = int(parts[0])
    return records

def save_results(records):
    sorted_items = sorted(records.items(), key=lambda x: x[1])[:MAX_WORKING]
    with open("tested.txt", "w", encoding="utf-8") as f:
        for orig_uri, ping in sorted_items:
            f.write(f"{ping:03d} {orig_uri}\n")
    with open("final.txt", "w", encoding="utf-8") as f:
        for orig_uri, _ in sorted_items:
            f.write(f"{orig_uri}\n")
    return dict(sorted_items)

def check_single_proxy(t_name, orig_uri, encoded_test_url):
    check_url = f"{MIHOMO_API}/proxies/{t_name}/delay?timeout=2000&url={encoded_test_url}&expected={EXPECTED_STATUS}"
    try:
        r = requests.get(check_url, timeout=3)
        if r.status_code == 200 and "delay" in r.json():
            ping = int(r.json()["delay"])
            if 0 < ping < MAX_PING:
                return orig_uri, ping
    except Exception:
        pass
    return None

def test_nodes_with_mihomo(nodes_to_test, existing_records):
    if not nodes_to_test:
        return existing_records

    temp_map = {}
    temp_uris = []
    for idx, orig_uri in enumerate(nodes_to_test):
        t_name = f"node_{idx}"
        temp_map[t_name] = orig_uri
        temp_uris.append(make_temp_uri(orig_uri, t_name))

    with open("temp_sub.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(temp_uris) + "\n")

    temp_config = {
        "external-controller": "127.0.0.1:9090",
        "proxy-providers": {
            "test_pool": {
                "type": "file",
                "path": "./temp_sub.txt"
            }
        }
    }
    with open("temp_mihomo.yaml", "w", encoding="utf-8") as f:
        yaml.dump(temp_config, f)

    mihomo_proc = subprocess.Popen(["./mihomo", "-f", "temp_mihomo.yaml"])
    time.sleep(3)

    encoded_test_url = urllib.parse.quote(TEST_URL, safe="")

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

                if len(existing_records) > MAX_WORKING:
                    existing_records = dict(sorted(existing_records.items(), key=lambda x: x[1])[:MAX_WORKING])

    mihomo_proc.terminate()
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
            print("Достигнут лимит времени работы (45 мин). Сохраняем прогресс и передаем эстафету.")
            break

        if len(tested_records) >= MAX_WORKING:
            print(f"Набрано {MAX_WORKING} рабочих серверов. Очищаем оставшиеся очереди.")
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

            if any(stripped.startswith(proto) for proto in PROTOCOLS):
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
        print("В test.txt остались необработанные строки. Запрашиваем перезапуск workflow.")
        set_github_output("has_more", "true")
    else:
        print("Все строки из test.txt успешно обработаны.")
        set_github_output("has_more", "false")

if __name__ == "__main__":
    main()
