Copiază exact:
python#!/usr/bin/env python3
"""
ML Service - Flask API pentru detectia SQL Injection
Snort trimite traficul aici, modelul returneaza verdictul
"""

from flask import Flask, request, jsonify
import numpy as np
import tensorflow as tf
import logging
from urllib.parse import unquote

tf.get_logger().setLevel('ERROR')

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MODEL_PATH = "snort_model_improved.h5"
model = None

def load_model():
    global model
    try:
        model = tf.keras.models.load_model(MODEL_PATH)
        logger.info("Model incarcat cu succes!")
    except Exception as e:
        logger.error(f"Eroare la incarcarea modelului: {e}")

def extract_features(param_string):
    param_lower = param_string.lower()
    param_decoded = unquote(param_lower)
    
    features = []
    features.append(min(len(param_string) / 200, 1.0))
    special_chars = sum(1 for c in param_string if c in "'\"-;()*/%=")
    features.append(min(special_chars / 20, 1.0))
    features.append(min(param_string.count('&') / 5, 1.0))
    digits = sum(1 for c in param_string if c.isdigit())
    features.append(min(digits / 30, 1.0))
    keywords = ["'", "or", "and", "select", "union", "drop", "--", ";", "=", "sleep", "benchmark"]
    for keyword in keywords:
        features.append(1.0 if keyword in param_decoded else 0.0)
    return features

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "model_loaded": model is not None})

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        param = data.get('param', '')
        
        features = extract_features(param)
        features_array = np.array([features])
        
        prediction = model.predict(features_array, verbose=0)[0][0]
        is_malicious = bool(prediction > 0.5)
        
        result = {
            "param": param,
            "score": float(prediction),
            "malicious": is_malicious,
            "verdict": "BLOCK" if is_malicious else "ALLOW"
        }
        
        if is_malicious:
            logger.warning(f"SQL INJECTION DETECTAT: {param} (score: {prediction:.4f})")
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    load_model()
    app.run(host='0.0.0.0', port=5000, debug=False)
