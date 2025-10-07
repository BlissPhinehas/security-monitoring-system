"""
Batch test multiple IPs
"""
import subprocess
import sys
import time
from pathlib import Path

# Make sure we're using the venv Python
python_exe = sys.executable

test_ips = [
    ("8.8.8.8", "Google DNS - Should be safe"),
    ("1.1.1.1", "Cloudflare DNS - Should be safe"),
    ("185.220.101.1", "Known Tor exit node - Might be flagged"),
]

print("=" * 70)
print("BATCH IP ANALYSIS TEST")
print("=" * 70)

for ip, description in test_ips:
    print(f"\n\nTesting: {ip} ({description})")
    print("-" * 70)
    
    subprocess.run([
        python_exe, "-m", "src.main", 
        "check-ip", ip
    ])
    
    print("\nWaiting 5 seconds before next test (API rate limiting)...")
    time.sleep(5)  # Be nice to the APIs

print("\n" + "=" * 70)
print("BATCH TEST COMPLETE")
print("=" * 70)

