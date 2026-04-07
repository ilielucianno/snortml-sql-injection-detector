#!/usr/bin/env python3
"""
Generate an improved dataset for SQL injection detection
"""

import json
import random

def generate_normal_request():
    patterns = [
        ("id", str(random.randint(1, 9999))),
        ("user", random.choice(["john", "alice", "bob", "admin", "guest"])),
        ("q", random.choice(["laptop", "phone", "computer", "monitor", "keyboard"])),
        ("category", random.choice(["electronics", "books", "clothing", "toys"])),
        ("page", str(random.randint(1, 100))),
        ("sort", random.choice(["asc", "desc", "price", "name"])),
        ("product", f"product={random.choice(['laptop','phone','monitor'])}&page={random.randint(1,20)}"),
        ("complex", f"search={random.choice(['laptop','phone','book'])}&limit={random.randint(5,50)}&sort={random.choice(['asc','desc'])}"),
    ]
    name, value = random.choice(patterns)
    return f"{name}={value}"

def generate_sql_injection():
    param_name = random.choice(["id", "user", "q", "search", "name", "product", "category"])
    
    attack_type = random.choice(["tautology", "union", "comment", "stacked", "boolean", "time_based", "drop_table"])
    
    if attack_type == "tautology":
        value = random.choice(["1' OR '1'='1", "1 OR 1=1", "' OR 'a'='a", "1' AND '1'='1"])
    elif attack_type == "union":
        value = random.choice([
            "1 UNION SELECT username, password FROM users",
            "1 UNION SELECT * FROM credit_cards",
            "1 UNION SELECT 1,2,3,4,5"
        ])
    elif attack_type == "comment":
        value = random.choice(["admin' --", "1' #", "1'/* comment */", "admin'--"])
    elif attack_type == "stacked":
        value = random.choice([
            "1; DROP TABLE users; --", "1; DELETE FROM logs; --",
            "1; INSERT INTO admin VALUES('hacker','pass')"
        ])
    elif attack_type == "boolean":
        value = random.choice(["1 AND 1=1", "1 AND 1=2", "1' AND '1'='1", "1' AND '1'='2"])
    elif attack_type == "time_based":
        value = random.choice([
            "1' OR SLEEP(5) --", "1' WAITFOR DELAY '00:00:05' --",
            "1' AND BENCHMARK(1000000,MD5('test')) --"
        ])
    else:
        value = random.choice(["1; DROP TABLE users --", "1' DROP TABLE products --"])
    
    return f"{param_name}={value}"

def extract_features(param_string):
    param_lower = param_string.lower()
    features = []
    features.append(min(len(param_string) / 200, 1.0))
    special_chars = sum(1 for c in param_string if c in "'\"-;()*/%=")
    features.append(min(special_chars / 20, 1.0))
    features.append(min(param_string.count('&') / 5, 1.0))
    digits = sum(1 for c in param_string if c.isdigit())
    features.append(min(digits / 30, 1.0))
    keywords = ["'", "or", "and", "select", "union", "drop", "--", ";", "=", "sleep", "benchmark"]
    for keyword in keywords:
        features.append(1.0 if keyword in param_lower else 0.0)
    return features

print("Generating improved dataset...")
data = []

print("Generating normal requests...")
for _ in range(8000):
    param = generate_normal_request()
    features = extract_features(param)
    data.append({"param": param, "features": features, "label": 0})

print("Generating SQL injection attacks...")
for _ in range(8000):
    param = generate_sql_injection()
    features = extract_features(param)
    data.append({"param": param, "features": features, "label": 1})

random.shuffle(data)
split_idx = int(len(data) * 0.8)
train_data = data[:split_idx]
test_data = data[split_idx:]

with open("train_dataset_improved.json", "w") as f:
    json.dump(train_data, f, indent=2)

with open("test_dataset_improved.json", "w") as f:
    json.dump(test_data, f, indent=2)

print(f"Total samples: {len(data)}")
print(f"Training samples: {len(train_data)}")
print(f"Test samples: {len(test_data)}")
