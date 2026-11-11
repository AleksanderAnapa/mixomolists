import base64
import hashlib
import os
import re
import subprocess
import time
import urllib.parse
import requests
import yaml

PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://", "ssr://", "hy2://", "hysteria2://", "tuic://")
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
    name = urllib.parse.quote(str(p.get("name", "node")))
    server = p.get("server")
    port = p.get("port")
    if not (server and port):
        return None
    if ptype == "ss":
        cipher = p.get("cipher", "")
        password = p.get("password", "")
        userinfo = base64.b64encode(f"{cipher}:{password}".encode()).decode()
        return f"ss://{userinfo}@{server}:{port}#{name}"
    elif ptype == "trojan":
        password = p.get("password", "")
        sni = p.get("sni", server)
        return f"trojan://{password}@{server}:{port}?sni={sni}#{name}"
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

    testing_list = sorted(list(all_nodes))
    with open("testing.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(testing_list) + ("\n" if testing_list else ""))

    tested_records = {}
    if os.path.exists("tested.txt"):
        with open("tested.txt", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(" ", 1)
                if len(parts) == 2 and parts[0].isdigit():
                    tested_records[parts[1]] = int(parts[0])

    combined_to_check = list(set(testing_list) | set(tested_records.keys()))

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
            check_url = f"{MIHOMO_API}/proxies/{t_name}/delay?timeout=4000&url=http://gstatic.com"
            try:
                r = requests.get(check_url, timeout=5)
                if r.status_code == 200 and "delay" in r.json():
                    ping = min(int(r.json()["delay"]), 999)
                    new_tested[orig_uri] = ping
            except Exception:
                pass

        mihomo_proc.terminate()

        sorted_items = sorted(new_tested.items(), key=lambda x: x[1])

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
