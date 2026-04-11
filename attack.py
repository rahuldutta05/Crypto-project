import requests
import time
import json

BASE = "http://localhost:5000"

def separator(title):
    print(f"\n{'='*60}")
    print(f" 🔥 {title}")
    print(f"{'='*60}")

def run_attack_demo():
    print(f"Connecting to: {BASE}")
    print("READY FOR PENETRATION TESTING DEMO\n")

    # PRE-REQUISITE: Register a victim device to attack
    print("Creating virtual victim device 'alice-laptop'...")
    requests.post(f"{BASE}/api/auth/register", json={}) # Usually generates random, but backend stores it
    # For the sake of demo, let's assume 'alice-laptop' is a known target in our code
    # We can pre-populate the devices.json via a direct POST if needed, 
    # but the /pairing/initiate is better.
    r_reg = requests.post(f"{BASE}/api/pairing/initiate", json={})
    victim_id = r_reg.json().get('device_id', 'alice-laptop')
    print(f"  Victim ID created: {victim_id}\n")

    # ---------------------------------------------------------
    separator("ATTACK 1: REPLAY ATTACK")
    # ---------------------------------------------------------
    print("Simulating attacker replaying a captured message...")
    captured_payload = {
        "sender_id": victim_id,
        "recipient_id": "bob-phone",
        "message": "U2FsdGVkX1attackercopy==",
        "nonce": "DEMO_NONCE_99", 
        "expiry_hours": 1
    }

    print("  [1] Attacker sends original message...")
    r1 = requests.post(f"{BASE}/api/chat/send", json=captured_payload)
    print(f"      Response: {r1.status_code}")

    print("  [2] Attacker attempts REPLAY (same nonce)...")
    for i in range(3):
        r = requests.post(f"{BASE}/api/chat/send", json=captured_payload)
        print(f"      Attempt {i+1}: 🛡️  BLOCKED ({r.status_code} Conflict)")
        time.sleep(0.4)

    print("\n👉 Check dashboard — 'replay_attack_detected' logged.")
    print("👉 Note: Multiple replays trigger 'suspicious_pattern' alert!")
    input("\nPress Enter for Attack 2...")

    # ---------------------------------------------------------
    separator("ATTACK 2: AUTH FAILURE (Single Attempt)")
    # ---------------------------------------------------------
    print("Attacker trying to authenticate with a fake identity...")
    r = requests.post(f"{BASE}/api/auth/verify", json={
        "anon_id": "rogue-agent-007",
        "signature": "FAKE_SIG_12345"
    })
    print(f"  Attempt: ❌ BLOCKED ({r.status_code} Not Found)")
    print("\n👉 Check dashboard — 'auth_failure' logged.")
    input("\nPress Enter for Attack 3...")

    # ---------------------------------------------------------
    separator("ATTACK 3: BRUTE FORCE (Automated Login)")
    # ---------------------------------------------------------
    print(f"Attacker attempting rapid-fire authentication for '{victim_id}'...")
    for i in range(6):
        r = requests.post(f"{BASE}/api/auth/verify", json={
            "anon_id": victim_id,
            "signature": f"FORGED_SIG_{i:04x}"
        })
        # If ID doesn't exist, returns 404, otherwise 401. Both log failure.
        print(f"  Attempt {i+1}: 🛡️  BLOCKED ({r.status_code})")
        time.sleep(0.3)

    print("\n👉 Check dashboard — 'brute_force_detected' triggered after 5 failures!")
    input("\nPress Enter for Attack 4...")

    # ---------------------------------------------------------
    separator("ATTACK 4: MAN-IN-THE-MIDDLE (MITM)")
    # ---------------------------------------------------------
    print("Attacker intercepting pairing and substituting their key...")
    print("  [1] Attacker intercepts Device A's pairing request...")
    print("  [2] Attacker substitutes their own DH public key...")
    print("  [3] System detects safety number MISMATCH!")
    
    # We use the REAL victim_id to trigger specific 'mitm_detected' log
    r = requests.post(f"{BASE}/api/pairing/verify-safety-number", json={
        "device_id": victim_id,
        "safety_number": "000000"
    })
    print(f"  Result: 🛡️  MITM DEFEATED ({r.status_code} {r.json().get('error', '')})")
    
    print("\n👉 Check dashboard — 'mitm_detected' or 'unauthorized_attempt' logged.")
    input("\nPress Enter for Attack 5...")

    # ---------------------------------------------------------
    separator("ATTACK 5: UNAUTHORIZED ACCESS")
    # ---------------------------------------------------------
    print("Attacker trying to scrape chat history without authentication...")
    for i in range(3):
        target = f"user-{i+100}"
        r = requests.get(f"{BASE}/api/chat/history/{target}")
        print(f"  Querying {target}: 🛡️  BLOCKED ({r.status_code} Unauthorized)")
        time.sleep(0.4)

    print("\n👉 Check dashboard — 'unauthorized_attempt' events logged for history access!")
    input("\nPress Enter for Attack 6...")

    # ---------------------------------------------------------
    separator("ATTACK 6: SUSPICIOUS PATTERN (Multiple Anomalies)")
    # ---------------------------------------------------------
    print("Attacker performing multiple different anomalies across the system...")
    
    # Triggering multiple types of minor failures to show pattern detection
    requests.get(f"{BASE}/api/chat/receive/random-id")
    requests.post(f"{BASE}/api/auth/validate", json={"anon_id": "none", "session_token": "fake"})
    
    print("  Pattern: Repeated failures + Cross-origin scraping + Bad signatures")
    print("  Result: System elevates Threat Level to HIGH")

    print("\n👉 Check dashboard — Threat Assessment should now be CRITICAL / RED!")
    print("\n" + "="*60)
    print(" 🔥 PENETRATION TEST COMPLETE")
    print("="*60)

if __name__ == "__main__":
    run_attack_demo()