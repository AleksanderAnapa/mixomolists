from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import subprocess
import time
import urllib.parse
import requests
import yaml

FAIL_FILE = "fail_counts.json"
MIHOMO_API = "http://127.0.0.1:9090"
MAX_FAILS = 20

URL_SCHEME = "https://"
URL_HOST = "://cloudflare.com"
URL_PATH = "/generate_204"
TEST_URL = URL_SCHEME + URL_HOST + URL_PATH

def make_temp_uri(original_uri, temp_name):
    if original_uri.startswith("vmess://"):
        return original_uri
    base_uri, _, _ = original_uri.partition("#")
    return f"{base_uri}#{temp_name}"

def check_node(t_name, orig_uri, encoded_test_url):
    check_url = f"{MIHOMO_API}/proxies/{t_name}/delay?timeout=4000&url={encoded_test_url}"
    try:
        r = requests.get(check_url, timeout=5)
        if r.status_code == 200 and "delay" in r.json() and int(r.json()["delay"]) > 0:
            return orig_uri, True
    except Exception:
        pass
    return orig_uri, False

def main():
    if not os.path.exists("final.txt"):
        print("Файл final.txt отсутствует. Стоп.")
        return

    with open("final.txt", "r", encoding="utf-8") as f:
        servers = [line.strip() for line in f if line.strip()]

    if not servers:
        print("Файл final.txt пустой. Стоп.")
        return

    fail_counts = {}
    if os.path.exists(FAIL_FILE):
        with open(FAIL_FILE, "r", encoding="utf-8") as f:
            fail_counts = json.load(f)

    temp_map = {}
    temp_uris = []
    for idx, orig_uri in enumerate(servers):
        t_name = f"mon_{idx}"
        temp_map[t_name] = orig_uri
        temp_uris.append(make_temp_uri(orig_uri, t_name))

    with open("temp_monitor_sub.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(temp_uris) + "\n")

    abs_mon_path = os.path.abspath("temp_monitor_sub.txt")
    temp_config = {
        "external-controller": "127.0.0.1:9090",
        "dns": {
            "enable": True,
            "ipv6": False,
            "nameserver": ["1.1.1.1", "8.8.8.8"]
        },
        "proxy-providers": {
            "final_pool": {
                "type": "file",
                "path": abs_mon_path
            }
        },
        "proxy-groups": [
            {
                "name": "AUTO",
                "type": "select",
                "use": ["final_pool"]
            }
        ]
    }
    with open("temp_monitor.yaml", "w", encoding="utf-8") as f:
        yaml.dump(temp_config, f)

    mihomo_proc = subprocess.Popen(["./mihomo", "-d", ".", "-f", "temp_monitor.yaml"])
    time.sleep(3)

    encoded_test_url = urllib.parse.quote(TEST_URL, safe="")
    results = {}

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = [
            executor.submit(check_node, t_name, orig_uri, encoded_test_url)
            for t_name, orig_uri in temp_map.items()
        ]
        for future in as_completed(futures):
            orig_uri, is_ok = future.result()
            results[orig_uri] = is_ok

    mihomo_proc.terminate()
    mihomo_proc.wait()

    alive_servers = []
    for orig_uri in servers:
        if results.get(orig_uri, False):
            fail_counts[orig_uri] = 0
        else:
            fail_counts[orig_uri] = fail_counts.get(orig_uri, 0) + 1

        if fail_counts.get(orig_uri, 0) < MAX_FAILS:
            alive_servers.append(orig_uri)
        else:
            print(f"Удален после {MAX_FAILS} неудач: {orig_uri[:40]}...")
            fail_counts.pop(orig_uri, None)

    with open("final.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(alive_servers) + ("\n" if alive_servers else ""))

    with open(FAIL_FILE, "w", encoding="utf-8") as f:
        json.dump(fail_counts, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    main()
