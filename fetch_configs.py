import requests
import base64
import json
import sys
from urllib.parse import urlparse, parse_qs, unquote

SOURCE_URL = "https://raw.githubusercontent.com/therealaleph/Iran-configs/refs/heads/main/ir_configs.txt"
OUTPUT_CONFIGS = "ir_configs.txt"
OUTPUT_BALANCER = "ir_balancer"
SUPPORTED_PROTOCOLS = ("ss://", "vless://", "vmess://", "trojan://")
BLOCKED_IPS = ("127.0.0.1",)


def fetch_raw(url):
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return response.text.strip()


def try_base64_decode(text):
    try:
        padded = text + "=" * (-len(text) % 4)
        decoded = base64.b64decode(padded).decode("utf-8")
        return decoded
    except Exception:
        return text


def extract_configs(text):
    configs = []
    skipped = 0
    for line in text.splitlines():
        line = line.strip()
        if not any(line.startswith(proto) for proto in SUPPORTED_PROTOCOLS):
            continue
        if any(ip in line for ip in BLOCKED_IPS):
            skipped += 1
            continue
        configs.append(line)
    if skipped:
        print(f"Skipped {skipped} config(s) with local/blocked IP.")
    return configs


def rename_config(line, index):
    new_name = f"IR - {index}"
    if "#" in line:
        base = line[:line.index("#")]
    else:
        base = line
    return base + "#" + new_name


def save_text(content, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def parse_vmess(line):
    try:
        encoded = line[len("vmess://"):]
        if "#" in encoded:
            encoded = encoded[:encoded.index("#")]
        padded = encoded + "=" * (-len(encoded) % 4)
        data = json.loads(base64.b64decode(padded).decode("utf-8"))
        return data
    except Exception:
        return None


def parse_vless(line):
    try:
        parsed = urlparse(line)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        return {
            "uuid": parsed.username,
            "address": parsed.hostname,
            "port": parsed.port,
            "params": params,
        }
    except Exception:
        return None


def parse_trojan(line):
    try:
        parsed = urlparse(line)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        return {
            "password": parsed.username,
            "address": parsed.hostname,
            "port": parsed.port,
            "params": params,
        }
    except Exception:
        return None


def parse_ss(line):
    try:
        raw = line[len("ss://"):]
        if "#" in raw:
            raw = raw[:raw.index("#")]
        if "?" in raw:
            raw = raw[:raw.index("?")]
        if "@" in raw:
            user_info, host_info = raw.rsplit("@", 1)
            try:
                padded = user_info + "=" * (-len(user_info) % 4)
                decoded_user = base64.b64decode(padded).decode("utf-8")
                if ":" in decoded_user:
                    method, password = decoded_user.split(":", 1)
                else:
                    method, password = decoded_user, ""
            except Exception:
                if ":" in user_info:
                    method, password = user_info.split(":", 1)
                else:
                    return None
            host, port_str = host_info.rsplit(":", 1)
            port = int(port_str)
        else:
            padded = raw + "=" * (-len(raw) % 4)
            decoded = base64.b64decode(padded).decode("utf-8")
            user_part, host_part = decoded.rsplit("@", 1)
            method, password = user_part.split(":", 1)
            host, port_str = host_part.rsplit(":", 1)
            port = int(port_str)
        return {
            "method": method,
            "password": password,
            "address": host,
            "port": port,
        }
    except Exception:
        return None


def build_security_settings(params):
    security = params.get("security", "none")
    if security == "tls":
        alpn_raw = params.get("alpn", "")
        alpn = [a for a in alpn_raw.split(",") if a] if alpn_raw else []
        tls = {"serverName": params.get("sni", params.get("host", ""))}
        if params.get("fp"):
            tls["fingerprint"] = params["fp"]
        if alpn:
            tls["alpn"] = alpn
        return "tls", {"tlsSettings": tls}
    elif security == "reality":
        reality = {
            "serverName": params.get("sni", ""),
            "fingerprint": params.get("fp", "chrome"),
            "publicKey": params.get("pbk", ""),
            "shortId": params.get("sid", ""),
        }
        if params.get("spx"):
            reality["spiderX"] = params["spx"]
        return "reality", {"realitySettings": reality}
    return "none", {}


def build_stream_settings(params, network=None):
    if network is None:
        network = params.get("type", "tcp")

    security, sec_fields = build_security_settings(params)
    stream = {"network": network, "security": security}
    stream.update(sec_fields)

    if network == "ws":
        ws = {"path": unquote(params.get("path", "/"))}
        host = params.get("host", "")
        if host:
            ws["headers"] = {"Host": host}
        stream["wsSettings"] = ws
    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": params.get("serviceName", params.get("path", "")),
            "multiMode": params.get("mode", "gun") == "multi",
        }
    elif network in ("h2", "http"):
        h2 = {"path": unquote(params.get("path", "/"))}
        host = params.get("host", "")
        if host:
            h2["host"] = [host]
        stream["httpSettings"] = h2
        stream["network"] = "h2"
    elif network == "tcp":
        header_type = params.get("headerType", "none")
        if header_type == "http":
            stream["tcpSettings"] = {
                "header": {
                    "type": "http",
                    "request": {
                        "path": [unquote(params.get("path", "/"))],
                        "headers": {"Host": [params.get("host", "")]},
                    },
                }
            }

    return stream


def build_vmess_outbound(data, tag):
    net = data.get("net", "tcp")
    params = {
        "type": net,
        "security": data.get("tls", "none"),
        "sni": data.get("sni", data.get("host", "")),
        "fp": data.get("fp", ""),
        "alpn": data.get("alpn", ""),
        "path": data.get("path", "/"),
        "host": data.get("host", ""),
        "serviceName": data.get("path", ""),
        "pbk": data.get("pbk", ""),
        "sid": data.get("sid", ""),
        "headerType": data.get("type", "none"),
    }
    return {
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": data.get("add", ""),
                    "port": int(data.get("port", 443)),
                    "users": [
                        {
                            "id": data.get("id", ""),
                            "alterId": int(data.get("aid", 0)),
                            "security": data.get("scy", "auto"),
                            "level": 8,
                        }
                    ],
                }
            ]
        },
        "streamSettings": build_stream_settings(params, network=net),
        "tag": tag,
    }


def build_vless_outbound(data, tag):
    return {
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": data["address"],
                    "port": data["port"],
                    "users": [
                        {
                            "id": data["uuid"],
                            "flow": data["params"].get("flow", ""),
                            "encryption": "none",
                            "level": 8,
                        }
                    ],
                }
            ]
        },
        "streamSettings": build_stream_settings(data["params"]),
        "tag": tag,
    }


def build_trojan_outbound(data, tag):
    return {
        "protocol": "trojan",
        "settings": {
            "servers": [
                {
                    "address": data["address"],
                    "port": data["port"],
                    "password": data["password"],
                    "level": 8,
                }
            ]
        },
        "streamSettings": build_stream_settings(data["params"]),
        "tag": tag,
    }


def build_ss_outbound(data, tag):
    return {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [
                {
                    "address": data["address"],
                    "port": data["port"],
                    "method": data["method"],
                    "password": data["password"],
                    "level": 8,
                }
            ]
        },
        "streamSettings": {"network": "tcp"},
        "tag": tag,
    }


def get_xray_template():
    return {
        "log": {"loglevel": "warning"},
        "remarks": "IR Multi Balanced",
        "dns": {
            "servers": [
                "https://dns.google/dns-query",
                "https://cloudflare-dns.com/dns-query",
                {
                    "address": "1.1.1.2",
                    "domains": ["domain:ir", "geosite:category-ir"],
                    "skipFallback": True,
                    "tag": "domestic-dns",
                },
            ]
        },
        "fakedns": [{"ipPool": "198.18.0.0/15", "poolSize": 10000}],
        "inbounds": [
            {
                "port": 10808,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
                "sniffing": {
                    "destOverride": ["http", "tls", "fakedns"],
                    "enabled": True,
                    "routeOnly": False,
                },
                "tag": "socks",
            }
        ],
        "observatory": {
            "enableConcurrency": True,
            "probeInterval": "3m",
            "probeUrl": "https://www.gstatic.com/generate_204",
            "subjectSelector": ["proxy-"],
        },
        "outbounds": [],
        "policy": {
            "levels": {
                "8": {
                    "connIdle": 300,
                    "downlinkOnly": 1,
                    "handshake": 4,
                    "uplinkOnly": 1,
                }
            },
            "system": {
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            },
        },
        "routing": {
            "balancers": [
                {
                    "selector": ["proxy-"],
                    "strategy": {"type": "leastPing"},
                    "tag": "proxy-round",
                }
            ],
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "inboundTag": ["socks"],
                    "outboundTag": "dns-out",
                    "port": "53",
                    "type": "field",
                },
                {"ip": ["geoip:private"], "outboundTag": "direct", "type": "field"},
                {
                    "domain": ["geosite:private"],
                    "outboundTag": "direct",
                    "type": "field",
                },
                {
                    "domain": ["domain:ir", "geosite:category-ir"],
                    "outboundTag": "direct",
                    "type": "field",
                },
                {"ip": ["geoip:ir"], "outboundTag": "direct", "type": "field"},
                {
                    "inboundTag": ["domestic-dns"],
                    "outboundTag": "direct",
                    "type": "field",
                },
                {
                    "balancerTag": "proxy-round",
                    "network": "tcp,udp",
                    "type": "field",
                },
            ],
        },
    }


def generate_balancer(configs, output_path):
    template = get_xray_template()
    outbounds = []
    index = 1

    for line in configs:
        line_lower = line.lower()
        outbound = None

        if line_lower.startswith("vmess://"):
            data = parse_vmess(line)
            if data:
                outbound = build_vmess_outbound(data, f"proxy-{index}")
        elif line_lower.startswith("vless://"):
            data = parse_vless(line)
            if data:
                outbound = build_vless_outbound(data, f"proxy-{index}")
        elif line_lower.startswith("trojan://"):
            data = parse_trojan(line)
            if data:
                outbound = build_trojan_outbound(data, f"proxy-{index}")
        elif line_lower.startswith("ss://"):
            data = parse_ss(line)
            if data:
                outbound = build_ss_outbound(data, f"proxy-{index}")

        if outbound:
            outbounds.append(outbound)
            index += 1

    outbounds.extend([
        {"protocol": "freedom", "settings": {}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"},
        {"protocol": "dns", "tag": "dns-out"},
    ])

    template["outbounds"] = outbounds

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(template, f, indent=2, ensure_ascii=False)

    print(f"Saved balancer with {index - 1} outbounds → {output_path}")


def main():
    try:
        print(f"Fetching: {SOURCE_URL}")
        raw = fetch_raw(SOURCE_URL)
        text = try_base64_decode(raw)
        configs = extract_configs(text)

        if not configs:
            print("No supported configs found. Exiting.")
            sys.exit(1)

        renamed = [rename_config(cfg, i) for i, cfg in enumerate(configs, start=1)]

        save_text("\n".join(renamed) + "\n", OUTPUT_CONFIGS)
        print(f"Saved {len(renamed)} configs → {OUTPUT_CONFIGS}")

        generate_balancer(renamed, OUTPUT_BALANCER)

    except requests.RequestException as e:
        print(f"Network error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()