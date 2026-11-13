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
