import json
import os
import subprocess
import time
import requests
import yaml

FAIL_FILE = "fail_counts.json"
MIHOMO_API = "http://127.0.0.1:9090"
MAX_FAILS = 20

def make_temp_uri(original_uri, temp_name):
    if original_uri.startswith("vmess://"):
        return original_uri
    base_uri = original_uri.split("#", 1)[0]
    return f"{base_uri}#{temp_name}"

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

    temp_config = {
        "external-controller": "127.0.0.1:9090",
        "proxy-providers": {
            "final_pool": {
                "type": "file",
                "path": "./temp_monitor_sub.txt"
            }
        }
    }
    with open("temp_monitor.yaml", "w", encoding="utf-8") as f:
        yaml.dump(temp_config, f)

    mihomo_proc = subprocess.Popen(["./mihomo", "-f", "temp_monitor.yaml"])
    time.sleep(3)

    alive_servers = []
    for idx, orig_uri in enumerate(servers):
        t_name = f"mon_{idx}"
        check_url = f"{MIHOMO_API}/proxies/{t_name}/delay?timeout=4000&url=http://gstatic.com"
        try:
            r = requests.get(check_url, timeout=5)
            if r.status_code == 200 and "delay" in r.json():
                fail_counts[orig_uri] = 0
            else:
                fail_counts[orig_uri] = fail_counts.get(orig_uri, 0) + 1
        except Exception:
            fail_counts[orig_uri] = fail_counts.get(orig_uri, 0) + 1

        if fail_counts.get(orig_uri, 0) < MAX_FAILS:
            alive_servers.append(orig_uri)
        else:
            print(f"Удален после {MAX_FAILS} неудач: {orig_uri[:40]}...")
            fail_counts.pop(orig_uri, None)

    mihomo_proc.terminate()

    with open("final.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(alive_servers) + ("\n" if alive_servers else ""))

    with open(FAIL_FILE, "w", encoding="utf-8") as f:
        json.dump(fail_counts, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    main()
