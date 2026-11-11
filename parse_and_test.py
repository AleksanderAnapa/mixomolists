import base64
import hashlib
import json
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
    # Конвертация базовых узлов из Clash YAML в URI-ссылки для единообразия
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
    # 1. Прямой поиск ссылок в тексте
    for line in text.splitlines():
        line = line.strip()
        if any(line.startswith(proto) for proto in PROTOCOLS):
            nodes.add(line)
    
    # 2. Попытка декодировать как Base64 подписку
    if not nodes:
        decoded = decode_base64_safe(text)
        for line in decoded.splitlines():
            line = line.strip()
            if any(line.startswith(proto) for proto in PROTOCOLS):
                nodes.add(line)

    # 3. Попытка разобрать как Clash YAML
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

def main():
    # Проверка изменения файла test.txt
    current_hash = get_file_hash("test.txt")
    old_hash = open(HASH_FILE).read().strip() if os.path.exists(HASH_FILE) else ""
    if current_hash == old_hash:
        print("Файл test.txt не изменялся. Выход.")
        return

    with open("test.txt", "r", encoding="utf-8", errors="ignore") as f:
        raw_lines = f.readlines()

    all_nodes = set()
    for line in raw_lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        
        # Если это готовая прокси-ссылка
        if any(line.startswith(proto) for proto in PROTOCOLS):
            all_nodes.add(line)
            continue

        # Если это HTTP/HTTPS ссылка (подписка или YAML)
        url_match = re.search(r"https?://[^\s]+", line)
        if url_match:
            url = url_match.group(0)
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200:
                    extracted = extract_nodes_from_text(resp.text)
                    all_nodes.update(extracted)
            except Exception:
                pass

    # Этап 2: Сохраняем все вытащенные серверы в testing.txt
    testing_list = sorted(list(all_nodes))
    with open("testing.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(testing_list) + "\n")

    if not testing_list:
        with open(HASH_FILE, "w") as f:
            f.write(current_hash)
        return

    # Формируем временный конфиг для ядра Mihomo через proxy-provider
    temp_config = {
        "external-controller": "127.0.0.1:9090",
        "proxy-providers": {
            "test_pool": {
                "type": "file",
                "path": "./testing.txt"
            }
        }
    }
    with open("temp_mihomo.yaml", "w", encoding="utf-8") as f:
        yaml.dump(temp_config, f)

    mihomo_proc = subprocess.Popen(["./mihomo", "-f", "temp_mihomo.yaml"])
    time.sleep(4)

    # Загружаем уже существующие серверы из tested.txt для перепроверки и сортировки
    tested_records = {}  # {server_uri: ping}
    if os.path.exists("tested.txt"):
        with open("tested.txt", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(" ", 1)
                if len(parts) == 2 and parts[0].isdigit():
                    tested_records[parts[1]] = int(parts[0])

    # Получаем список загруженных прокси из API Mihomo
    try:
        proxies_data = requests.get(f"{MIHOMO_API}/proxies", timeout=5).json().get("proxies", {})
    except Exception:
        proxies_data = {}

    # Сопоставляем имена в Mihomo с исходными URI (Mihomo берет имя после #)
    uri_by_name = {}
    for uri in testing_list:
        if "#" in uri:
            raw_name = urllib.parse.unquote(uri.split("#", 1)[1]).strip()
            uri_by_name[raw_name] = uri

    # Проверяем каждый узел через API Mihomo
    for proxy_name, info in proxies_data.items():
        if info.get("type") in ("Direct", "Reject", "Selector", "URLTest", "Fallback", "LoadBalance"):
            continue
        uri = uri_by_name.get(proxy_name)
        if not uri:
            continue

        encoded_name = urllib.parse.quote(proxy_name, safe="")
        check_url = f"{MIHOMO_API}/proxies/{encoded_name}/delay?timeout=4000&url=http://gstatic.com"
        try:
            r = requests.get(check_url, timeout=5)
            if r.status_code == 200 and "delay" in r.json():
                ping = min(int(r.json()["delay"]), 999)
                tested_records[uri] = ping
            else:
                tested_records.pop(uri, None)
        except Exception:
            tested_records.pop(uri, None)

    mihomo_proc.terminate()

    # Сортируем по пингу и записываем tested.txt (формат: "127 vless://...")
    sorted_items = sorted(tested_records.items(), key=lambda x: x[1])
    with open("tested.txt", "w", encoding="utf-8") as f:
        for uri, ping in sorted_items:
            f.write(f"{ping:03d} {uri}\n")

    # Записываем финальный отсортированный список без пинга в final.txt
    with open("final.txt", "w", encoding="utf-8") as f:
        for uri, _ in sorted_items:
            f.write(f"{uri}\n")

    # Обновляем хеш test.txt и сбрасываем счетчик ошибок для monitor.py
    with open(HASH_FILE, "w") as f:
        f.write(current_hash)
    if os.path.exists("fail_counts.json"):
        os.remove("fail_counts.json")

if __name__ == "__main__":
    main()
