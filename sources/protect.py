import os
import hashlib
import time
import math
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# === Settings ===
SIGNATURES = [
    "EICAR", "exec(", "subprocess", "powershell -enc", "cmd.exe /c",
    "base64.b64decode(", "import socket", "CreateRemoteThread", "VirtualAllocEx"
]
BLACKLIST_HASHES = {"275a021bbfb6482916d2c3dd7696f7b4"}
WHITELIST_HASHES = set()
DELETE_SUSPICIOUS = True
LOG_PATH = f"realtime_av_log_{int(time.time())}.txt"

# === Utility Functions ===
def get_md5(path):
    try:
        with open(path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except:
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
    except:
        return 0.0

def read_text(path):
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read()
    except:
        return ""

def log_findings(path, findings):
    with open(LOG_PATH, "a") as log:
        log.write(f"\n[{path}]\n")
        for entry in findings:
            log.write(f"  - {entry}\n")
    print(f"[!] Threat detected: {path}")

# === Scanner ===
def scan_file(path):
    results = []
    score = 0

    md5 = get_md5(path)
    if not md5 or md5 in WHITELIST_HASHES:
        return []

    content = read_text(path)
    entropy = get_entropy(path)

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
            results.append(f"Suspicious (score {score}), but not deleted.")
    except Exception as e:
        results.append(f"Delete failed: {e}")

    return results

# === File Watcher ===
class AVHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            findings = scan_file(event.src_path)
            if findings:
                log_findings(event.src_path, findings)

    def on_modified(self, event):
        if not event.is_directory:
            findings = scan_file(event.src_path)
            if findings:
                log_findings(event.src_path, findings)

# === Main ===
def main():
    path = "C:\\"  # Full disk monitoring
    print(f"🔒 Real-Time Antivirus Running on {path}...\nLog: {LOG_PATH}")
    observer = Observer()
    handler = AVHandler()
    observer.schedule(handler, path=path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
