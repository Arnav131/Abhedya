
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import json
from ai_engine.honeypot_llm import generate_decoy_passwords_llm

def main():
    
    input_data = sys.stdin.read()
    try:
        data = json.loads(input_data)
        real_password = data.get("real_password")
        n = data.get("n", 4)
        if not real_password:
            print(json.dumps({"error": "Missing 'real_password' in input"}))
            return
        result = generate_decoy_passwords_llm(real_password, n=n)
        print(json.dumps({"decoy_passwords": result}))
    except Exception as e:
        print(json.dumps({"error": str(e)}))

if __name__ == "__main__":
    main()
