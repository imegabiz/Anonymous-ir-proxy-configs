import requests
import base64
import sys

SOURCE_URL = "https://raw.githubusercontent.com/therealaleph/Iran-configs/refs/heads/main/ir_configs.txt"
OUTPUT_FILE = "ir_configs.txt"
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
    new_name = f"Anonymous - IR - {index}"
    if "#" in line:
        base = line[:line.index("#")]
    else:
        base = line
    return base + "#" + new_name


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

        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(renamed) + "\n")

        print(f"Saved {len(renamed)} configs -> {OUTPUT_FILE}")

    except requests.RequestException as e:
        print(f"Network error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()