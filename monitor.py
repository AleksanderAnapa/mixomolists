import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import subprocess
import tempfile
import time
import urllib.parse
import requests
import yaml

FAIL_FILE = "fail_counts.json"
MAX_FAILS = 20
MAX_WORKERS = 15
BASE_PORT = 9200

TEST_URL = base64.b64decode("aHR0cHM6Ly9jcC5jbG91ZGZsYXJlLmNvbS9nZW5lcmF0ZV8yMDQ=").decode("utf-8")
LOCAL_API_HOST = base64.b64decode("aHR0cDovLzEyNy4wLjAuMQ==").decode("utf-8")

def set_github_output(name, value):
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a", encoding="utf-8") as f:
            f.write(f"{name}={value}\n")

def test_one_server_isolated(orig_uri, slot_id, encoded_test_url):
    """Тестирует оригинальную ссылку 1-в-1 через провайдер Mihomo без изменения параметров."""
    if orig_uri.startswith("vmess://"):
        test_uri = orig_uri
    else:
        base = orig_uri.rpartition("#")[0] if "#" in orig_uri else orig_uri
        test_uri = f"{base}#single_node"

    b64_sub = base64.b64encode((test_uri + "\n").encode("utf-8")).decode("utf-8")
    api_port = BASE_PORT + slot_id

    fd_sub, sub_path = tempfile.mkstemp(prefix=f"msub_{slot_id}_", suffix=".txt", dir=".")
    os.close(fd_sub)
    fd_cfg, cfg_path = tempfile.mkstemp(prefix=f"mon_{slot_id}_", suffix=".yaml", dir=".")
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
        time.sleep(1.0)

        if proc.poll() is not None:
            return orig_uri, False

        r_list = requests.get(f"{LOCAL_API_HOST}:{api_port}/proxies", timeout=3)
        if r_list.status_code != 200:
            return orig_uri, False

        proxies_dict = r_list.json().get("proxies", {})
        target_name = None
        for pname in proxies_dict.keys():
            if pname not in ("DIRECT", "REJECT", "GLOBAL", "AUTO", "COMPATIBLE", "PASS"):
                target_name = pname
                break

        if not target_name:
            return orig_uri, False

        enc_name = urllib.parse.quote(target_name, safe="")
        check_url = f"{LOCAL_API_HOST}:{api_port}/proxies/{enc_name}/delay?timeout=4000&url={encoded_test_url}&expected=204"
        r = requests.get(check_url, timeout=5)
        if r.status_code == 200 and "delay" in r.json() and int(r.json()["delay"]) > 0:
            return orig_uri, True
        return orig_uri, False
    except Exception:
        return orig_uri, False
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
def main():
    if not os.path.exists("final.txt"):
        print("Файл final.txt отсутствует. Запрашиваем пополнение.")
        set_github_output("need_refill", "true")
        return

    with open("final.txt", "r", encoding="utf-8") as f:
        servers = [line.strip() for line in f if line.strip()]

    if not servers:
        print("Файл final.txt пустой. Запрашиваем пополнение.")
        set_github_output("need_refill", "true")
        return

    fail_counts = {}
    if os.path.exists(FAIL_FILE):
        with open(FAIL_FILE, "r", encoding="utf-8") as f:
            fail_counts = json.load(f)

    encoded_test_url = urllib.parse.quote(TEST_URL, safe="")
    results = {}

    for start_idx in range(0, len(servers), MAX_WORKERS):
        wave = servers[start_idx:start_idx + MAX_WORKERS]
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [
                executor.submit(test_one_server_isolated, orig_uri, slot, encoded_test_url)
                for slot, orig_uri in enumerate(wave)
            ]
            for future in as_completed(futures):
                orig_uri, is_ok = future.result()
                results[orig_uri] = is_ok

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

    if not alive_servers:
        print("Все серверы в final.txt оказались мертвыми. Запрашиваем пополнение.")
        set_github_output("need_refill", "true")
    else:
        print(f"Осталось живых серверов в final.txt: {len(alive_servers)}")
        set_github_output("need_refill", "false")

if __name__ == "__main__":
    main()
