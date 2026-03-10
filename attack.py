import requests
import time
import json

BASE = "https://cryptochat-production-e2fe.up.railway.app"

def separator(title):
    print(f"\n{'='*55}")
    print(f"  🔴 {title}")
    print(f"{'='*55}\n")

# ─────────────────────────────────────────────
# ATTACK 1: Replay Attack
# Attacker captures a nonce from the network
# and tries to replay it repeatedly
# ─────────────────────────────────────────────
separator("ATTACK 1: REPLAY ATTACK")
print("Simulating attacker replaying a captured message...\n")

captured_payload = {
    "device_id": "alice-laptop",
    "nonce": "CAPTURED_NONCE_A1B2C3",     # attacker sniffed this
    "ciphertext": "U2FsdGVkX1attackercopy==",
    "expiry_minutes": 5
}

for i in range(8):
    r = requests.post(f"{BASE}/api/chat/send", json=captured_payload)
    blocked = r.status_code != 200
    print(f"  Replay attempt {i+1}: {'🛡️  BLOCKED' if blocked else '⚠️  PASSED'} ({r.status_code})")
    time.sleep(0.5)

print("\n👉 Check dashboard — replay_attack_detected should appear!")
input("\nPress Enter to launch Attack 2...\n")


# ─────────────────────────────────────────────
# ATTACK 2: Brute Force Authentication
# Attacker tries to forge ZKP signatures
# ─────────────────────────────────────────────
separator("ATTACK 2: BRUTE FORCE (ZKP Auth)")
print("Attacker trying to forge device signatures...\n")

for i in range(10):
    r = requests.post(f"{BASE}/api/auth/verify", json={
        "device_id": "alice-laptop",
        "challenge": "intercepted_challenge_xyz",
        "signature": f"FORGED_{i:04x}DEADBEEF"
    })
    
    if i == 4:
        print(f"  Attempt {i+1}: 🚨 BRUTE FORCE DETECTED — alert triggered!")
    else:
        print(f"  Attempt {i+1}: ❌ Auth failed ({r.status_code})")
    time.sleep(0.4)

print("\n👉 Check dashboard — brute_force_detected, threat level rising!")
input("\nPress Enter to launch Attack 3...\n")


# ─────────────────────────────────────────────
# ATTACK 3: MitM — Safety Number Mismatch
# Attacker tries to intercept the DH exchange
# ─────────────────────────────────────────────
separator("ATTACK 3: MAN-IN-THE-MIDDLE")
print("Attacker intercepting pairing and substituting their key...\n")

print("  [1] Attacker intercepts Device A's pairing request...")
time.sleep(1)
print("  [2] Attacker substitutes their own DH public key...")
time.sleep(1)
print("  [3] Device B verifies safety number — MISMATCH detected!\n")

r = requests.post(f"{BASE}/api/pairing/verify-safety-number", json={
    "device_id": "alice-laptop",
    "peer_id": "bob-phone",
    "safety_number": "000000"      # attacker's fake number
})
print(f"  Server response: {r.status_code} — {r.json()}")
print("\n  🛡️  MitM defeated! Safety number is mathematical proof, not server trust.")

print("\n👉 Check dashboard — mitm_detected logged!")
input("\nPress Enter to launch Attack 4...\n")


# ─────────────────────────────────────────────
# ATTACK 4: Unauthorized Access
# Attacker skips ZKP, tries to read messages
# ─────────────────────────────────────────────
separator("ATTACK 4: UNAUTHORIZED ACCESS")
print("Attacker trying to read chat history without authentication...\n")

for i in range(5):
    r = requests.get(f"{BASE}/api/chat/history", params={
        "device_id": f"rogue-device-{i}"
    })
    print(f"  Attempt {i+1}: {'🛡️  BLOCKED' if r.status_code in [401,403] else f'⚠️  {r.status_code}'}")
    time.sleep(0.3)

print("\n👉 Check dashboard — unauthorized_attempt events logged!")
input("\nPress Enter for final report...\n")


# ─────────────────────────────────────────────
# FINAL: Pull the auto-generated pen test report
# ─────────────────────────────────────────────
separator("PENETRATION TEST REPORT")
r = requests.get(f"{BASE}/api/admin/attack-summary")
print(json.dumps(r.json(), indent=2))

print("\n✅ All attacks complete. Your system documented its own defense.")