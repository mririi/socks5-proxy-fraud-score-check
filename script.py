import socket
import socks
import requests
from contextlib import contextmanager

# =======================
# CONFIG
# =======================

INPUT_FILE = "socks5.txt"
OUTPUT_FILE = "clean_socks5.txt"
IP_ECHO_URL = "https://api.ipify.org"
REQUEST_TIMEOUT = 15

IP2LOCATION_API_KEY = "ADD_KEY_HERE"

# =======================
# SOCKS5 CONTEXT
# =======================

@contextmanager
def socks_proxy(proxy_line: str):
    """
    Supports proxy format:
    host:port:username:password
    """
    original_socket = socket.socket

    parts = proxy_line.strip().split(":")

    if len(parts) < 4:
        raise ValueError(f"Invalid proxy format: {proxy_line}")

    host = parts[0]
    port = int(parts[1])
    username = parts[2]
    password = ":".join(parts[3:])  # safe if password contains :

    socks.set_default_proxy(
        socks.SOCKS5,
        host,
        port,
        username=username,
        password=password
    )

    socket.socket = socks.socksocket
    try:
        yield
    finally:
        socket.socket = original_socket

# =======================
# NETWORK FUNCTIONS
# =======================

def get_public_ip(proxy_line: str) -> str:
    """
    Resolves public IP using the given SOCKS5 proxy.
    """
    with socks_proxy(proxy_line):
        r = requests.get(IP_ECHO_URL, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.text.strip()

# =======================
# IP2LOCATION FRAUD CHECK
# =======================

def get_fraud_score(ip: str) -> int:
    url = "https://api.ip2location.io/"
    params = {
        "key": IP2LOCATION_API_KEY,
        "ip": ip,
        "format": "json",
        "source": "fraud"
    }

    r = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    data = r.json()

    if "fraud_score" not in data:
        raise RuntimeError(f"Fraud API not enabled or bad response: {data}")

    return int(data["fraud_score"])

# =======================
# FILE IO
# =======================

def load_proxies(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def save_proxies(path: str, proxies):
    with open(path, "w", encoding="utf-8") as f:
        for p in proxies:
            f.write(p + "\n")

# =======================
# MAIN
# =======================

def main():
    proxies = load_proxies(INPUT_FILE)

    clean_proxies = []
    ip_cache = {}

    for proxy in proxies:
        try:
            ip = get_public_ip(proxy)

            if ip not in ip_cache:
                ip_cache[ip] = get_fraud_score(ip)

            score = ip_cache[ip]

            print(f"{proxy} -> {ip} -> fraud_score={score}")

            if score == 0:
                clean_proxies.append(proxy)

        except Exception as e:
            print(f"{proxy} FAILED: {e}")

    save_proxies(OUTPUT_FILE, clean_proxies)

    print("\n========== SUMMARY ==========")
    print(f"Total proxies checked: {len(proxies)}")
    print(f"Clean proxies saved:  {len(clean_proxies)}")
    print(f"Output file: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
