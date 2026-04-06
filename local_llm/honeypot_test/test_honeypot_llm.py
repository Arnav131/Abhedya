import sys
import os
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
from ai_engine.honeypot_llm import generate_decoy_passwords_llm, honey_response

def test_generate_decoy_passwords_llm():
    real_password = "Abc123!@#"
    decoys = generate_decoy_passwords_llm(real_password, n=4)
    print("Generated decoy passwords:", decoys)
    assert len(decoys) == 4
    for pwd in decoys:
        assert len(pwd) == len(real_password)
        assert pwd != real_password

def test_honey_response():
    decoys = ["Xyz789$%^", "Qwe456&*()", "Rty321!@#", "Uio654#@!"]
    response = honey_response(decoys)
    print("Honey response:", response)
    assert response in decoys

def run_all_tests():
    test_generate_decoy_passwords_llm()
    test_honey_response()
    print("All tests passed.")

if __name__ == "__main__":
    run_all_tests()
