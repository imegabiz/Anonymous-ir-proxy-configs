import requests
import base64
import sys

SOURCE_URL = "https://raw.githubusercontent.com/therealaleph/Iran-configs/refs/heads/main/ir_configs.txt"
OUTPUT_FILE = "ir_configs.txt"
SUPPORTED_PROTOCOLS = ("ss://", "vless://", "vmess://", "trojan://")
BLOCKED_IPS = ("127.0.0.1",)


def fetch_raw(url: str) -> str:
    """Download raw content from the URL."""
    print(f"Fetching: {url}")
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return response.text.strip()


def try_base64_decode(text: str) -> str:
    """
    Try to decode text as base64.
    If it fails or the result is not readable UTF-8, return the original text.
    """
    try:
        padded = text + "=" * (-len(text) % 4)
        decoded = base64.b64decode(padded).decode("utf-8")
        return decoded
    except Exception:
        return text


def extract_configs(text: str) -> list[str]:
    """Extract lines that start with a supported protocol and have no blocked IPs."""
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


def rename_config(line: str, index: int) -> str:
    """
    Replace (or add) the name fragment (#...) at the end of a config line
    with 'IR - N'. The rest of the config is left completely untouched.
    """
    new_name = f"IR - {index}"
    if "#" in line:
        base = line[: line.index("#")]
    else:
        base = line
    return base + "#" + new_name


def save_configs(configs: list[str], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(configs) + "\n")
    print(f"Saved {len(configs)} configs → {path}")


def main():
    try:
        raw = fetch_raw(SOURCE_URL)
        text = try_base64_decode(raw)
        configs = extract_configs(text)

        if not configs:
            print("No supported configs found. Exiting without overwriting output file.")
            sys.exit(1)

        renamed = [rename_config(cfg, i) for i, cfg in enumerate(configs, start=1)]
        save_configs(renamed, OUTPUT_FILE)

    except requests.RequestException as e:
        print(f"Network error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
