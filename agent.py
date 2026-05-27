import nmap
import socket
import requests
import time
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

RAILWAY_URL = os.environ.get(
    "RAILWAY_URL",
    "https://cctv-monitoringsystem-networkadministration-production.up.railway.app",
)
AGENT_KEY = os.environ.get("AGENT_KEY", "")
SCAN_INTERVAL_SECONDS = 60  # mag-sscan every 1 minute


def get_local_network():
    """Kunin yung local IP at network range ng PC."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split(".")
        network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return network, local_ip
    except Exception as e:
        print(f"[ERROR] Cannot determine local network: {e}")
        return "192.168.1.0/24", "unknown"


def scan_network(network):
    """Mag-scan ng network gamit nmap."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Scanning {network}...")
    devices = []

    try:
        nm = nmap.PortScanner()
        # -sn = ping scan (walang port scan, mas mabilis)
        # --host-timeout = hindi mag-aantay ng matagal sa isang host
        nm.scan(hosts=network, arguments="-sn --host-timeout 5s")

        for host in nm.all_hosts():
            # Kunin ang hostname
            hostname = "Unknown"
            try:
                resolved = socket.gethostbyaddr(host)[0]
                hostname = resolved
            except Exception:
                if nm[host].hostname():
                    hostname = nm[host].hostname()

            # Kunin ang MAC address at vendor
            mac = "N/A"
            vendor = "Unknown"
            try:
                if "mac" in nm[host]["addresses"]:
                    mac = nm[host]["addresses"]["mac"]
                if "vendor" in nm[host] and mac in nm[host]["vendor"]:
                    vendor = nm[host]["vendor"][mac]
            except Exception:
                pass

            # Determine device type based sa hostname at vendor
            device_type = guess_device_type(hostname, vendor, host)

            devices.append(
                {
                    "ip": host,
                    "hostname": hostname if hostname != "Unknown" else device_type,
                    "mac": mac,
                    "vendor": vendor,
                    "device_type": device_type,
                    "status": "active",
                }
            )

            print(f"  Found: {host} — {hostname} ({vendor})")

    except nmap.PortScannerError as e:
        print(f"[ERROR] nmap error: {e}")
        print("[INFO] Make sure nmap is installed: https://nmap.org/download.html")
    except Exception as e:
        print(f"[ERROR] Scan error: {e}")

    return devices


def guess_device_type(hostname, vendor, ip):
    """Hulaan ang device type base sa hostname at vendor."""
    hostname_lower = hostname.lower()
    vendor_lower = vendor.lower()

    # Router / Gateway
    if any(
        x in hostname_lower
        for x in [
            "router",
            "gateway",
            "gw",
            "dlink",
            "tplink",
            "asus",
            "linksys",
            "netgear",
        ]
    ):
        return "🌐 Router"
    if any(
        x in vendor_lower
        for x in [
            "tp-link",
            "d-link",
            "asus",
            "linksys",
            "netgear",
            "cisco",
            "ubiquiti",
        ]
    ):
        return "🌐 Router/AP"

    # Camera
    if any(
        x in hostname_lower
        for x in ["cam", "camera", "ipc", "nvr", "dvr", "hikvision", "dahua"]
    ):
        return "📷 IP Camera"
    if any(
        x in vendor_lower for x in ["hikvision", "dahua", "axis", "reolink", "amcrest"]
    ):
        return "📷 IP Camera"

    # Phone / Mobile
    if any(
        x in vendor_lower
        for x in ["apple", "samsung", "xiaomi", "oppo", "vivo", "huawei", "oneplus"]
    ):
        return "📱 Mobile Device"
    if any(x in hostname_lower for x in ["iphone", "android", "phone", "mobile"]):
        return "📱 Mobile Device"

    # PC / Laptop
    if any(
        x in hostname_lower
        for x in ["desktop", "laptop", "pc", "computer", "workstation"]
    ):
        return "💻 PC/Laptop"
    if any(
        x in vendor_lower
        for x in ["intel", "realtek", "dell", "hp", "lenovo", "acer", "asus"]
    ):
        return "💻 PC/Laptop"

    # Printer
    if any(
        x in hostname_lower
        for x in ["printer", "print", "epson", "canon", "brother", "hp"]
    ):
        return "🖨️ Printer"

    # Smart TV
    if any(
        x in hostname_lower for x in ["tv", "smart-tv", "roku", "firetv", "chromecast"]
    ):
        return "📺 Smart TV"

    # Server
    if any(x in hostname_lower for x in ["server", "nas", "synology", "qnap"]):
        return "🖥️ Server/NAS"

    # Last resort — yung IP ending
    parts = ip.split(".")
    if parts[-1] == "1":
        return "🌐 Gateway"

    return "🔌 Network Device"


def send_to_railway(devices):
    """I-send ang scan results sa Railway server."""
    url = f"{RAILWAY_URL.rstrip('/')}/api/network/update"
    headers = {
        "Content-Type": "application/json",
        "X-Agent-Key": AGENT_KEY,
    }
    payload = {"devices": devices}

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=15)
        if response.status_code == 200:
            print(
                f"[{datetime.now().strftime('%H:%M:%S')}] ✅ Sent {len(devices)} devices to Railway"
            )
        else:
            print(
                f"[{datetime.now().strftime('%H:%M:%S')}] ❌ Server error: {response.status_code} — {response.text}"
            )
    except requests.exceptions.ConnectionError:
        print(
            f"[{datetime.now().strftime('%H:%M:%S')}] ❌ Cannot connect to Railway — check RAILWAY_URL"
        )
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ❌ Send error: {e}")


def main():
    print("=" * 50)
    print("  CCTV Monitor — Local Network Agent")
    print("=" * 50)
    print(f"  Railway URL : {RAILWAY_URL}")
    print(f"  Scan every  : {SCAN_INTERVAL_SECONDS} seconds")
    print("=" * 50)
    print()

    if RAILWAY_URL == "https://your-app.railway.app":
        print("[WARNING] RAILWAY_URL is not set! Edit agent.py or create a .env file.")
        print("  Add: RAILWAY_URL=https://your-actual-app.railway.app")
        print()

    while True:
        network, local_ip = get_local_network()
        print(f"[INFO] Local IP: {local_ip} | Network: {network}")

        devices = scan_network(network)

        if devices:
            send_to_railway(devices)
        else:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] No devices found")

        print(f"[INFO] Next scan in {SCAN_INTERVAL_SECONDS} seconds...\n")
        time.sleep(SCAN_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
