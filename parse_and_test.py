import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import json
import operator
import os
import re
import socket
import subprocess
import tempfile
import time
import urllib.parse
import requests
import yaml

PROTOCOLS = ("vless://", "vmess://", "trojan://")
ALLOWED_COUNTRY_CODES = ("us", "de", "nl", "fr", "gb")
MAX_PING = 1000
MAX_WORKING = 30
BATCH_SIZE = 1
MAX_WORKERS = 15
BASE_PORT = 9100
MAX_RUNTIME_SECONDS = 2700

TEST_URL = "https" + "://" + "cp." + "cloudflare.com" + "/generate_204"
CIDR_BASE_URL = "https" + "://" + "raw." + "githubusercontent.com" + "/herrbischoff/country-ip-blocks/master/ipv4/"

def log_debug(msg):
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
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
            port = int(d["port"])
            if not (1 <= port <= 65535):
                return None
            net = str(d.get("net", "tcp")).strip().lower()
            if net not in ("tcp", "ws", "grpc", "http", "h2", "httpupgrade"):
                return None
            tls = str(d.get("tls", "")).lower() in ("tls", "1", "true")
            scy = str(d.get("scy", "auto")).strip().lower()
            if scy in ("null", "none", ""):
                scy = "auto"
            proxy = {
                "name": temp_name,
                "type": "vmess",
                "server": str(d["add"]).strip(),
                "port": port,
                "uuid": str(d["id"]).strip(),
                "alterId": int(d.get("aid", 0)),
                "cipher": scy,
                "udp": True,
                "tls": tls,
                "skip-cert-verify": True,
                "network": net
            }
            if d.get("sni"):
                proxy["servername"] = str(d["sni"]).strip()
            elif d.get("host"):
                proxy["servername"] = str(d["host"]).strip()
            if net == "ws":
                proxy["ws-opts"] = {
                    "path": str(d.get("path", "/")).strip() or "/",
                    "headers": {"Host": str(d.get("host", d["add"])).strip()}
                }
            elif net == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": str(d.get("path", "")).strip()}
            return proxy

        parsed = urllib.parse.urlparse(uri)
        params = urllib.parse.parse_qs(parsed.query)
        def get_p(k, default=""):
            vals = params.get(k)
            return str(next(iter(vals))).strip() if vals else default

        if not (parsed.hostname and parsed.port and parsed.username):
            return None
        if not (1 <= int(parsed.port) <= 65535):
            return None

        net = get_p("type", "tcp").lower()
        if net not in ("tcp", "ws", "grpc", "http", "h2", "httpupgrade", "xhttp", "splithttp"):
            return None
        security = get_p("security", "none").lower()
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
                proxy["client-fingerprint"] = get_p("fp", "chrome") or "chrome"
            if net == "ws":
                proxy["ws-opts"] = {
                    "path": get_p("path", "/") or "/",
                    "headers": {"Host": get_p("host", sni) or sni}
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
                    "path": get_p("path", "/") or "/",
                    "headers": {"Host": get_p("host", sni) or sni}
                }
            elif net == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": get_p("serviceName", "")}
            return proxy
    except Exception:
        return None
    return None

def build_clean_uri(orig_uri, idx, country_code="UN"):
    """Пересобирает ссылку с нуля и добавляет двухбуквенный код страны (например, 01_US)."""
    tag = f"{idx:02d}_{country_code.upper()}"
    try:
        if orig_uri.startswith("vmess://"):
            raw_b64 = orig_uri.replace("vmess://", "", 1)
            b64_part, _, _ = raw_b64.partition("#")
            d = json.loads(decode_base64_safe(b64_part))
            scy = str(d.get("scy", "auto")).strip().lower()
            if scy in ("null", "none", ""):
                scy = "auto"
            clean_d = {
                "v": "2",
                "ps": tag,
                "add": str(d["add"]).strip(),
                "port": str(int(d["port"])),
                "id": str(d["id"]).strip(),
                "aid": str(int(d.get("aid", 0))),
                "scy": scy,
                "net": str(d.get("net", "tcp")).strip(),
                "type": "none",
                "host": str(d.get("host", "")).strip(),
                "path": str(d.get("path", "")).strip(),
                "tls": str(d.get("tls", "")).strip(),
                "sni": str(d.get("sni", "")).strip()
            }
            new_b64 = base64.b64encode(json.dumps(clean_d, separators=(",", ":")).encode("utf-8")).decode("utf-8")
            return f"vmess://{new_b64}"

        parsed = urllib.parse.urlparse(orig_uri)
        params = urllib.parse.parse_qs(parsed.query)
        def get_p(k, default=""):
            vals = params.get(k)
            return str(next(iter(vals))).strip() if vals else default

        net = get_p("type", "tcp").lower()
        security = get_p("security", "none").lower()
        sni = get_p("sni") or get_p("peer") or str(parsed.hostname)

        q = {"type": net}
        if orig_uri.startswith("vless://"):
            q["encryption"] = "none"
            q["security"] = security
            if security in ("tls", "reality"):
                q["sni"] = sni
                q["fp"] = get_p("fp", "chrome") or "chrome"
            if security == "reality":
                q["pbk"] = get_p("pbk")
                sid = get_p("sid", "")
                if sid:
                    q["sid"] = sid
            flow = get_p("flow")
            if flow:
                q["flow"] = flow
            if net == "ws":
                q["path"] = get_p("path", "/") or "/"
                q["host"] = get_p("host", sni) or sni
            elif net == "grpc":
                q["serviceName"] = get_p("serviceName", "")
            query_str = urllib.parse.urlencode(q, safe="/")
            return f"vless://{parsed.username}@{parsed.hostname}:{parsed.port}?{query_str}#{tag}"

        if orig_uri.startswith("trojan://"):
            q["security"] = "tls"
            q["sni"] = sni
            if net == "ws":
                q["path"] = get_p("path", "/") or "/"
                q["host"] = get_p("host", sni) or sni
            elif net == "grpc":
                q["serviceName"] = get_p("serviceName", "")
            query_str = urllib.parse.urlencode(q, safe="/")
            return f"trojan://{parsed.username}@{parsed.hostname}:{parsed.port}?{query_str}#{tag}"
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
    networks_by_code = {}
    total = 0
    for code in ALLOWED_COUNTRY_CODES:
        url = CIDR_BASE_URL + f"{code}.cidr"
        nets = []
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        nets.append(ipaddress.ip_network(line))
        except Exception as e:
            log_debug(f"Ошибка загрузки подсетей {code}: {e}")
        networks_by_code[code.upper()] = nets
        total += len(nets)
    log_debug(f"Загружено CIDR-подсетей стран: {total}")
    return networks_by_code

def resolve_host_country(host, networks_by_code):
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(1.5)
    try:
        ip_str = socket.gethostbyname(host)
        ip_obj = ipaddress.ip_address(ip_str)
        for code, nets in networks_by_code.items():
            if any(ip_obj in net for net in nets):
                return host, code
        return host, None
    except Exception:
        return host, None
    finally:
        socket.setdefaulttimeout(old_timeout)

def filter_by_country(uris, networks_by_code, dns_cache):
    has_any_nets = any(len(v) > 0 for v in networks_by_code.values())
    if not has_any_nets:
        return uris

    hosts_to_resolve = set()
    uri_hosts = []
    for uri in uris:
        host = extract_host(uri)
        uri_hosts.append((uri, host))
        if host and host not in dns_cache:
            hosts_to_resolve.add(host)

    if hosts_to_resolve:
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = [executor.submit(resolve_host_country, h, networks_by_code) for h in hosts_to_resolve]
            for future in as_completed(futures):
                h, code = future.result()
                dns_cache[h] = code

    return [uri for uri, host in uri_hosts if host and dns_cache.get(host)]

def load_tested_records():
    records = {}
    if os.path.exists("tested.txt"):
        with open("tested.txt", "r", encoding="utf-8") as f:
            for line in f:
                ping_str, sep, orig_uri = line.strip().partition(" ")
                if sep and ping_str.isdigit():
                    records[orig_uri] = int(ping_str)
    return records

def save_results(records, dns_cache=None, networks_by_code=None):
    sorted_items = sorted(records.items(), key=operator.itemgetter(1))[:MAX_WORKING]
    with open("tested.txt", "w", encoding="utf-8") as f:
        for orig_uri, ping in sorted_items:
            f.write(f"{ping:03d} {orig_uri}\n")
    with open("final.txt", "w", encoding="utf-8") as f:
        idx = 1
        for orig_uri, _ in sorted_items:
            host = extract_host(orig_uri)
            c_code = dns_cache.get(host) if dns_cache else None
            if not c_code and host and networks_by_code:
                _, c_code = resolve_host_country(host, networks_by_code)
                if dns_cache is not None:
                    dns_cache[host] = c_code
            clean = build_clean_uri(orig_uri, idx, c_code or "Node")
            if clean:
                f.write(f"{clean}\n")
                idx += 1
    return dict(sorted_items)
def test_one_server_isolated(orig_uri, slot_id, encoded_test_url):
    p_dict = uri_to_clash_dict(orig_uri, "single_node")
    if not p_dict:
        return orig_uri, 0, "INVALID_FORMAT"

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

    fd, cfg_path = tempfile.mkstemp(prefix=f"mihomo_{slot_id}_", suffix=".yaml", dir=".")
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
            return orig_uri, 0, "MIHOMO_REJECTED_NODE"

        api_base = "http" + "://" + f"127.0.0.1:{api_port}"
        check_url = f"{api_base}/proxies/single_node/delay?timeout=3500&url={encoded_test_url}&expected=204"
        r = requests.get(check_url, timeout=4.5)
        if r.status_code == 200 and "delay" in r.json():
            ping = int(r.json()["delay"])
            if 0 < ping < MAX_PING:
                return orig_uri, ping, "OK"
            return orig_uri, ping, f"HIGH_PING({ping})"
        return orig_uri, 0, f"HTTP_{r.status_code}"
    except Exception as e:
        return orig_uri, 0, f"ERR:{e}"
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()
        if os.path.exists(cfg_path):
            os.remove(cfg_path)

def test_nodes_individually(nodes_to_test, existing_records, dns_cache=None, networks_by_code=None):
    if not nodes_to_test:
        return existing_records

    encoded_test_url = urllib.parse.quote(TEST_URL, safe="")

    for start_idx in range(0, len(nodes_to_test), MAX_WORKERS):
        if len(existing_records) >= MAX_WORKING:
            break

        wave = nodes_to_test[start_idx:start_idx + MAX_WORKERS]
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [
                executor.submit(test_one_server_isolated, orig_uri, slot, encoded_test_url)
                for slot, orig_uri in enumerate(wave)
            ]
            for future in as_completed(futures):
                orig_uri, ping, status = future.result()
                if status == "OK":
                    if orig_uri not in existing_records or ping < existing_records[orig_uri]:
                        existing_records[orig_uri] = ping
                    log_debug(f"[OK {ping}ms] ({len(existing_records)}/{MAX_WORKING}) {orig_uri[:55]}")

        if existing_records:
            existing_records = save_results(existing_records, dns_cache, networks_by_code)

    return existing_records

def has_unprocessed_lines(lines):
    for line in lines:
        s = line.strip()
        if s and not s.startswith("#"):
            return True
    return False

def main():
    with open("debug_log.txt", "w", encoding="utf-8") as f:
        f.write("=== СТАРТ ИНДИВИДУАЛЬНОЙ ПРОВЕРКИ ===\n")

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

    networks_by_code = load_country_networks()
    dns_cache = {}
    tested_records = load_tested_records()

    if tested_records:
        log_debug(f"Перепроверка {len(tested_records)} существующих серверов...")
        rechecked = test_nodes_individually(list(tested_records.keys()), {}, dns_cache, networks_by_code)
        tested_records = save_results(rechecked, dns_cache, networks_by_code)

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
            log_debug(f"Обработка строки: {stripped[:65]}")

            if any(stripped.startswith(proto) for proto in PROTOCOLS) and uri_to_clash_dict(stripped, "test"):
                batch_nodes.add(stripped)
                continue

            url_match = re.search(r"https?://[^\s]+", stripped)
            if url_match:
                url = url_match.group(0)
                try:
                    resp = requests.get(url, timeout=10)
                    if resp.status_code == 200:
                        extracted = extract_nodes_from_text(resp.text)
                        log_debug(f"Извлечено валидных URI: {len(extracted)}")
                        batch_nodes.update(extracted)
                except Exception as e:
                    log_debug(f"Ошибка скачивания {url[:45]}: {e}")

        geo_nodes = filter_by_country(list(batch_nodes), networks_by_code, dns_cache)
        unique_geo_nodes = sorted(list(set(geo_nodes)))
        log_debug(f"После фильтра стран осталось: {len(unique_geo_nodes)}")

        with open("testing.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(unique_geo_nodes) + ("\n" if unique_geo_nodes else ""))

        if unique_geo_nodes:
            new_candidates = [u for u in unique_geo_nodes if u not in tested_records]
            tested_records = test_nodes_individually(new_candidates, tested_records, dns_cache, networks_by_code)
            tested_records = save_results(tested_records, dns_cache, networks_by_code)

        lines = new_lines
        with open("test.txt", "w", encoding="utf-8") as f:
            f.writelines(lines)
        log_debug(f"Строка завершена. Итого рабочих: {len(tested_records)}/{MAX_WORKING}")

    if os.path.exists("fail_counts.json"):
        os.remove("fail_counts.json")

    if has_unprocessed_lines(lines):
        set_github_output("has_more", "true")
    else:
        set_github_output("has_more", "false")

if __name__ == "__main__":
    main()
