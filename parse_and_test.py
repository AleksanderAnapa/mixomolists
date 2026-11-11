import base64
import hashlib
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
ALLOWED_COUNTRIES = {"US", "DE", "NL", "FR", "GB"}
MAX_PING = 200
MAX_WORKING = 30

HASH_FILE = ".test_hash"
MIHOMO_API = "http://127.0.0.1:9090"

def get_file_hash(filepath):
    if not os.path.exists(filepath):
        return ""
    with open(filepath, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

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

def filter_by_country(uris):
    host_to_uris = {}
    for uri in uris:
        host = extract_host(uri)
        if host:
            host_to_uris.setdefault(host, []).append(uri)

    ip_to_hosts = {}
    for host in host_to_uris:
        try:
            ip = socket.gethostbyname(host)
            ip_to_hosts.setdefault(ip, []).append(host)
        except Exception:
            continue

    ips = list(ip_to_hosts.keys())
    allowed_uris = []

    for i in range(0, len(ips), 100):
        batch = ips[i:i + 100]
        try:
            resp = requests.post(
                "http://ip-api.com",
                json=batch,
                timeout=10
            )
            if resp.status_code == 200:
                for item in resp.json():
                    if item.get("status") == "success" and item.get("countryCode") in ALLOWED_COUNTRIES:
                        ip = item.get("query")
                        for h in ip_to_hosts.get(ip, []):
                            allowed_uris.extend(host_to_uris[h])
            time.sleep(1.5)
        except Exception:
            pass

    return allowed_uris

def make_temp_uri(original_uri, temp_name):
    if original_uri.startswith("vmess://"):
        return original_uri
    base_uri = original_uri.split("#", 1)[0]
    return f"{base_uri}#{temp_name}"

def main():
    if not os.path.exists("test.txt"):
        print("Файл test.txt не найден.")
        return

    current_hash = get_file_hash("test.txt")
    old_hash = open(HASH_FILE).read().strip() if os.path.exists(HASH_FILE) else ""
    if current_hash == old_hash:
        print("Файл test.txt не изменялся. Выход.")
        return

    with open("test.txt", "r", encoding="utf-8", errors="ignore") as f:
        raw_lines = f.readlines()

    all_nodes = set()
    remaining_lines = []

    for raw_line in raw_lines:
        stripped = raw_line.strip()
        
        if not stripped or stripped.startswith("#"):
            remaining_lines.append(raw_line)
            continue
        
        if any(stripped.startswith(proto) for proto in PROTOCOLS):
            all_nodes.add(stripped)
            continue

        url_match = re.search(r"https?://[^\s]+", stripped)
        if url_match:
            url = url_match.group(0)
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200:
                    extracted = extract_nodes_from_text(resp.text)
                    all_nodes.update(extracted)
            except Exception:
                pass
            continue

        continue

    print(f"Всего извлечено узлов (VLESS/VMess/Trojan): {len(all_nodes)}. Проверка стран...")
    geo_filtered_nodes = filter_by_country(list(all_nodes))
    print(f"После фильтрации по странам осталось: {len(geo_filtered_nodes)}")

    testing_list = sorted(list(set(geo_filtered_nodes)))
    with open("testing.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(testing_list) + ("\n" if testing_list else ""))

    tested_records = {}
    if os.path.exists("tested.txt"):
        with open("tested.txt", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(" ", 1)
                if len(parts) == 2 and parts[0].isdigit():
                    tested_records[parts[1]] = int(parts[0])

    combined_to_check = list(tested_records.keys()) + [u for u in testing_list if u not in tested_records]

    if combined_to_check:
        temp_map = {}
        temp_uris = []
        for idx, orig_uri in enumerate(combined_to_check):
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
        time.sleep(4)

        new_tested = {}
        for t_name, orig_uri in temp_map.items():
            if len(new_tested) >= MAX_WORKING:
                print(f"Достигнут лимит в {MAX_WORKING} рабочих серверов. Остановка проверки.")
                break

            check_url = f"{MIHOMO_API}/proxies/{t_name}/delay?timeout=2000&url=http://gstatic.com"
            try:
                r = requests.get(check_url, timeout=3)
                if r.status_code == 200 and "delay" in r.json():
                    ping = int(r.json()["delay"])
                    if ping < MAX_PING:
                        new_tested[orig_uri] = ping
                        print(f"[{len(new_tested)}/{MAX_WORKING}] OK ({ping} ms)")
            except Exception:
                pass

        mihomo_proc.terminate()

        sorted_items = sorted(new_tested.items(), key=lambda x: x[1])[:MAX_WORKING]

        with open("tested.txt", "w", encoding="utf-8") as f:
            for orig_uri, ping in sorted_items:
                f.write(f"{ping:03d} {orig_uri}\n")

        with open("final.txt", "w", encoding="utf-8") as f:
            for orig_uri, _ in sorted_items:
                f.write(f"{orig_uri}\n")

    with open("test.txt", "w", encoding="utf-8") as f:
        f.writelines(remaining_lines)

    new_hash = get_file_hash("test.txt")
    with open(HASH_FILE, "w", encoding="utf-8") as f:
        f.write(new_hash)

    if os.path.exists("fail_counts.json"):
        os.remove("fail_counts.json")

if __name__ == "__main__":
    main()
