import random
import sys
import time

import requests

API = "http://127.0.0.1:8000"

SAFE_PROMPTS = [
    "What is the capital of France?",
    "Can you explain how a binary search algorithm works in Python?",
    "Translate 'Good morning' to Spanish.",
    "Write a short poem about a cat and a dog playing in the rain.",
    "Summarize the plot of the movie Inception.",
    "What are some healthy breakfast options?",
    "How do you say 'thank you' in Japanese?",
    "Explain the theory of relativity to a 5-year-old.",
    "List 5 tips for improving productivity.",
    "What is the weather usually like in Tokyo during spring?"
]

def generate_safe(count=300):
    print(f"✅ Generating {count} SAFE prompts to balance the dashboard...")
    
    success = 0
    errors = 0
    
    for i in range(count):
        payload = random.choice(SAFE_PROMPTS)
        try:
            res = requests.post(
                f"{API}/api/v1/scan/test",
                json={"prompt": payload, "model": "gpt-4o", "scan_type": "prompt"},
                timeout=5
            )
            if res.status_code == 200:
                success += 1
                if i % 10 == 0:
                    print(f"  [{i+1}/{count}] Sent safe prompt... (Status: {res.json().get('action')})")
            else:
                errors += 1
        except Exception:
            errors += 1
            
        time.sleep(random.uniform(0.01, 0.05))
        
    print(f"\n✅ Finished generation. {success} successful, {errors} errors.")
    print("Refresh your dashboard to see the BLUE/SAFE metrics increase!")

if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    generate_safe(count)
