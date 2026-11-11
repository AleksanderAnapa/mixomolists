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

    # Запускаем Mihomo для проверки final.txt
    temp_config = {
        "external-controller": "127.0.0.1:9090",
        "proxy-providers": {
            "final_pool": {
                "type": "file",
                "path": "./final.txt"
            }
        }
    }
    with open("temp_monitor.yaml", "w", encoding="utf-8") as f:
        yaml.dump(temp_config, f)

    mihomo_proc = subprocess.Popen(["./mihomo", "-f", "temp_monitor.yaml"])
    time.sleep(3)

    try:
        proxies_data = requests.get(f"{MIHOMO_API}/proxies", timeout=5).json().get("proxies", {})
    except Exception:
        proxies_data = {}

    uri_by_name = {}
    for uri in servers:
        if "#" in uri:
            raw_name = urllib.parse.unquote(uri.split("#", 1)[1]).strip()
            uri_by_name[raw_name] = uri

    alive_servers = []
    for uri in servers:
        raw_name = urllib.parse.unquote(uri.split("#", 1)[1]).strip() if "#" in uri else ""
        if not raw_name or raw_name not in proxies_data:
            fail_counts[uri] = fail_counts.get(uri, 0) + 1
        else:
            encoded_name = urllib.parse.quote(raw_name, safe="")
            check_url = f"{MIHOMO_API}/proxies/{encoded_name}/delay?timeout=4000&url=http://gstatic.com"
            try:
                r = requests.get(check_url, timeout=5)
                if r.status_code == 200 and "delay" in r.json():
                    fail_counts[uri] = 0  # Сбрасываем счетчик при успешном ответе
                else:
                    fail_counts[uri] = fail_counts.get(uri, 0) + 1
            except Exception:
                fail_counts[uri] = fail_counts.get(uri, 0) + 1

        if fail_counts.get(uri, 0) < MAX_FAILS:
            alive_servers.append(uri)
        else:
            print(f"Удален после {MAX_FAILS} неудач: {uri[:40]}...")
            fail_counts.pop(uri, None)

    mihomo_proc.terminate()

    with open("final.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(alive_servers) + ("\n" if alive_servers else ""))

    with open(FAIL_FILE, "w", encoding="utf-8") as f:
        json.dump(fail_counts, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    main()
