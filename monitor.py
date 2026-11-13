import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import re
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

TEST_URL = "https" + "://" + "cp." + "cloudflare.com" + "/generate_204"

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
                sid = get_p("sid", "")
                if not pbk:
                    return None
                if sid and (len(sid) > 16 or len(sid) % 2 != 0 or not re.fullmatch(r"[0-9a-fA-F]+", sid)):
                    return None
                proxy["reality-opts"] = {
                    "public-key": pbk,
                    "short-id": sid
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

def test_one_server_isolated(orig_uri, slot_id, encoded_test_url):
    p_dict = uri_to_clash_dict(orig_uri, "single_node")
    if not p_dict:
        return orig_uri, False

    api_port = BASE_PORT + slot_id
    temp_config = {
        "external-controller": f"127.0.0.1:{api_port}",
        "dns": {
            "enable": True,
            "ipv6": False,
            "nameserver": ["1.1.1.1", "8.8.8.8"]
        },
        "proxies": [p_dict],
        "proxy-groups": [
            {
                "name": "AUTO",
                "type": "select",
                "proxies": ["single_node"]
            }
        ]
    }

    fd, cfg_path = tempfile.mkstemp(prefix=f"mon_{slot_id}_", suffix=".yaml", dir=".")
    os.close(fd)
    proc = None
    try:
        with open(cfg_path, "w", encoding="utf-8") as f:
            yaml.dump(temp_config, f, allow_unicode=True)

        proc = subprocess.Popen(
            ["./mihomo", "-d", ".", "-f", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(0.8)

        if proc.poll() is not None:
            return orig_uri, False

        api_base = "http" + "://" + f"127.0.0.1:{api_port}"
        check_url = f"{api_base}/proxies/single_node/delay?timeout=4000&url={encoded_test_url}&expected=204"
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

if __name__ == "__main__":
    main()
