

import re
import random
from transformers import pipeline

generator = pipeline(
    "text-generation",
    model="distilgpt2",   
    device=-1
)

def build_prompt(real_password: str) -> str:
    """
    Force LLM to generate password-like outputs
    """
    return f"""
Generate 5 strong random passwords similar in style to: {real_password}

Rules:
- Same length: {len(real_password)}
- Include uppercase, lowercase, numbers, symbols
- Do NOT explain anything
- Output only passwords (one per line)

Passwords:
"""

def clean_passwords(text: str, target_length: int):
    lines = text.split("\n")
    passwords = []
    for line in lines:
        line = line.strip()
        
        line = re.sub(r"[^a-zA-Z0-9!@#$%^&*]", "", line)
        if len(line) == target_length:
            passwords.append(line)
    return list(set(passwords))

def generate_decoy_passwords_llm(real_password: str, n=4):
    prompt = build_prompt(real_password)
    result = generator(
        prompt,
        max_length=100,
        num_return_sequences=1,
        temperature=0.9,
        top_k=50,
        do_sample=True
    )
    raw_output = result[0]["generated_text"]
    candidates = clean_passwords(raw_output, len(real_password))


    if len(candidates) < n:
        candidates.extend(fallback_generate(real_password, n - len(candidates)))
    return candidates[:n]


import string

def fallback_generate(real_password, n):
    charset = string.ascii_letters + string.digits + "!@#$%^&*"
    return [
        ''.join(random.choice(charset) for _ in range(len(real_password)))
        for _ in range(n)
    ]

def honey_response(decoys: list):
    return random.choice(decoys) if decoys else None

def generate_fake_secrets_llm():
    prompt = """
Generate realistic-looking fake credentials:

Format:
stripe_key=
aws_key=
jwt_secret=
db_password=

Only output values.
"""
    result = generator(prompt, max_length=100, temperature=0.8)
    return result[0]["generated_text"]

"""
#services 
from ai_engine.honeypot_llm import generate_decoy_passwords_llm

def store_password_flow(real_password):
    decoys = generate_decoy_passwords_llm(real_password, n=4)
    all_passwords = [real_password] + decoys
    return all_passwords

    
#views
from ai_engine.honeypot_llm import honey_response

def retrieve_with_honey(decoys, is_valid_key, real_password):
    if is_valid_key:
        return real_password
    else:
        return honey_response(decoys)

"""

