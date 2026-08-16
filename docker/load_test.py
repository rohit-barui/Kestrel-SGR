import os
import threading
import time

import requests

TARGET = os.getenv('TARGET_URL', 'http://localhost:9090')
NUM_REQUESTS = int(os.getenv('NUM_REQUESTS', '100'))
CONCURRENCY = int(os.getenv('CONCURRENCY', '10'))

# Simple payload used for load testing – a benign email
payload = {
    "email": "test@example.com",
    "subject": "Hello",
    "body": "Just a test email with a safe link https://example.com"
}

results = []

def worker():
    while True:
        try:
            idx = len(results)
        except Exception:
            idx = 0
        if idx >= NUM_REQUESTS:
            break
        start = time.time()
        try:
            r = requests.post(f"{TARGET}/api/scan", json=payload, timeout=10)
            elapsed = time.time() - start
            results.append((r.status_code, elapsed))
        except Exception:
            results.append((None, time.time() - start))
        if len(results) >= NUM_REQUESTS:
            break

threads = []
for _ in range(CONCURRENCY):
    t = threading.Thread(target=worker)
    t.start()
    threads.append(t)

for t in threads:
    t.join()

# Report
success = sum(1 for code, _ in results if code == 200)
fail = len(results) - success
avg_latency = sum(lat for _, lat in results if lat) / len(results) if results else 0
print(f"Requests: {len(results)}  Success: {success}  Fail: {fail}  Avg latency: {avg_latency:.3f}s")
