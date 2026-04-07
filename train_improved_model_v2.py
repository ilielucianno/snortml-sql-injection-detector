#!/usr/bin/env python3
"""
Train improved neural network for SQL injection detection
"""

import json
import numpy as np
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, BatchNormalization, Input
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau

print("Loading training data...")
with open("train_dataset_improved.json", "r") as f:
    train_data = json.load(f)

with open("test_dataset_improved.json", "r") as f:
    test_data = json.load(f)

print(f"Training samples: {len(train_data)}")
print(f"Test samples: {len(test_data)}")

X_train = np.array([item["features"] for item in train_data])
y_train = np.array([item["label"] for item in train_data])
X_test = np.array([item["features"] for item in test_data])
y_test = np.array([item["label"] for item in test_data])

print(f"Features shape: {X_train.shape[1]} features per sample")

model = Sequential([
    Input(shape=(X_train.shape[1],)),
    Dense(64, activation='relu'),
    BatchNormalization(),
    Dropout(0.3),
    Dense(32, activation='relu'),
    BatchNormalization(),
    Dropout(0.2),
    Dense(16, activation='relu'),
    Dropout(0.2),
    Dense(8, activation='relu'),
    Dense(1, activation='sigmoid')
])

optimizer = Adam(learning_rate=0.0005)
model.compile(optimizer=optimizer, loss='binary_crossentropy', metrics=['accuracy', 'precision', 'recall'])

early_stop = EarlyStopping(monitor='val_loss', patience=15, restore_best_weights=True)
reduce_lr = ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=5, min_lr=0.00001)

print("\nTraining model...")
history = model.fit(X_train, y_train, validation_split=0.2, epochs=150, batch_size=64, callbacks=[early_stop, reduce_lr], verbose=1)

test_loss, test_acc, test_prec, test_rec = model.evaluate(X_test, y_test, verbose=0)
print(f"\nTest Accuracy: {test_acc:.4f}")
print(f"Test Precision: {test_prec:.4f}")
print(f"Test Recall: {test_rec:.4f}")

model.save("snort_model_improved.keras")
model.save("snort_model_improved.h5")
print("\nModel saved as 'snort_model_improved.keras' and 'snort_model_improved.h5'")

test_cases = [
    ("id=123", 0, "Simple ID"),
    ("q=laptop", 0, "Simple search"),
    ("id=1' OR '1'='1", 1, "SQL Injection"),
    ("username=admin' --", 1, "SQL Injection"),
    ("product=laptop&page=2", 0, "Multiple params"),
]

def extract_features_simple(param_str):
    param_lower = param_str.lower()
    features = []
    features.append(min(len(param_str) / 200, 1.0))
    special_chars = sum(1 for c in param_str if c in "'\"-;()*/%=")
    features.append(min(special_chars / 20, 1.0))
    features.append(min(param_str.count('&') / 5, 1.0))
    digits = sum(1 for c in param_str if c.isdigit())
    features.append(min(digits / 30, 1.0))
    keywords = ["'", "or", "and", "select", "union", "drop", "--", ";", "=", "sleep", "benchmark"]
    for keyword in keywords:
        features.append(1.0 if keyword in param_lower else 0.0)
    return features

print("\n=== Testing on examples ===")
for param_str, expected, desc in test_cases:
    features = extract_features_simple(param_str)
    pred = model.predict(np.array([features]), verbose=0)[0][0]
    verdict = "MALICIOUS" if pred > 0.5 else "NORMAL"
    status = "✅" if ((pred > 0.5 and expected == 1) or (pred <= 0.5 and expected == 0)) else "❌"
    print(f"{status} {desc:20} | {param_str:35} | Pred: {pred:.4f} | Expected: {expected} | {verdict}")
