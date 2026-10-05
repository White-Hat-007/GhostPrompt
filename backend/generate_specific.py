import random
import time

import requests

API = "http://127.0.0.1:8000"

MEDIUM_ATTACKS = [
    # Phone numbers / PII (Medium severity in GhostPrompt PII detector)
    "My phone number is 555-123-4567. Please call me back.",
    "Can you verify the contact number +44 20 7123 4567?",
    "The emergency contact for this account is 1-800-555-0199.",
    "Her international mobile is +1-555-987-6543.",
    "Please send the receipt to john.doe@example.com",
    "Forward the instructions to support@company.org",
    "Contact me at admin@internal.network"
]

SAFE_PROMPTS = [
    "What is the capital of France?",
    "Can you explain how a binary search algorithm works in Python?",
    "Translate 'Good morning' to Spanish.",
    "Write a short poem about a cat and a dog playing in the rain.",
    "Summarize the plot of the movie Inception."
]

def generate_specific(medium_count=7, safe_count=5):
    print(f"🔥 Generating {medium_count} medium threats and {safe_count} safe prompts...")
    
    # Send Medium
    for i in range(medium_count):
        payload = random.choice(MEDIUM_ATTACKS)
        try:
            res = requests.post(
                f"{API}/api/v1/scan/test",
                json={"prompt": payload, "model": "gpt-4o", "scan_type": "prompt"},
                timeout=5
            )
            print(f"  [Medium {i+1}/{medium_count}] Status: {res.json().get('action')} | Prompt: {payload[:30]}...")
        except Exception as e:
            print(f"  [Error] {e}")
        time.sleep(0.5)

    # Send Safe
    for i in range(safe_count):
        payload = random.choice(SAFE_PROMPTS)
        try:
            res = requests.post(
                f"{API}/api/v1/scan/test",
                json={"prompt": payload, "model": "gpt-4o", "scan_type": "prompt"},
                timeout=5
            )
            print(f"  [Safe {i+1}/{safe_count}] Status: {res.json().get('action')} | Prompt: {payload[:30]}...")
        except Exception as e:
            print(f"  [Error] {e}")
        time.sleep(0.5)
        
    print("\n✅ Finished generation.")

if __name__ == "__main__":
    generate_specific()
