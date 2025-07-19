import os
import hashlib
import time
import math

LOG_PATH = f"scan_log_{int(time.time())}.txt"

SIGNATURES = [
    "EICAR", "exec(", "subprocess", "powershell -enc", "cmd.exe /c",
    "base64.b64decode(", "import socket", "CreateRemoteThread", "VirtualAllocEx"
]

BLACKLIST_HASHES = {"275a021bbfb6482916d2c3dd7696f7b4"}
WHITELIST_HASHES = set()

DELETE_SUSPICIOUS = True

def get_md5(path):
    try:
        with open(path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except Exception:
        return None

def get_entropy(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        entropy = 0.0
        for f in freq:
            if f:
                p = f / len(data)
                entropy -= p * math.log2(p)
        return round(entropy, 2)
    except Exception:
        return 0.0

def read_text(path):
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""

def scan_file(path):
    results = []
    score = 0
    md5 = get_md5(path)
    entropy = get_entropy(path)

    if md5 in WHITELIST_HASHES:
        return []

    content = read_text(path)
    for sig in SIGNATURES:
        if sig in content:
            score += 1
            results.append(f"Signature match: {sig}")

    if md5 in BLACKLIST_HASHES:
        score += 2
        results.append(f"Blacklisted hash: {md5}")

    if entropy > 7.5:
        score += 1
        results.append(f"High entropy: {entropy}")

    try:
        if score > 0 and DELETE_SUSPICIOUS:
            os.remove(path)
            results.append("Suspicious file deleted.")
        elif score > 0:
            results.append(f"Score: {score} (File not deleted)")
    except Exception as e:
        results.append(f"Delete failed: {e}")

    return results

def scan_directory(root):
    script_path = os.path.abspath(__file__)
    with open(LOG_PATH, "w") as log:
        for dirpath, _, files in os.walk(root):
            for fname in files:
                full_path = os.path.abspath(os.path.join(dirpath, fname))
                if full_path == script_path:
                    continue
                findings = scan_file(full_path)
                if findings:
                    log.write(f"\n[{full_path}]\n")
                    for entry in findings:
                        log.write(f"  - {entry}\n")
    print(f"Scan complete. Log saved: {LOG_PATH}")

def main():
    print("Antivirus Scanner")
    target = input("Enter folder to scan: ").strip()
    if os.path.isdir(target):
        scan_directory(target)
    else:
        print("Invalid directory.")

if __name__ == "__main__":
    main()
