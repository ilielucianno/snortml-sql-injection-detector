# SnortML SQL Injection Detector

A project where I trained a Machine Learning model (TensorFlow) to detect SQL injection attacks, as an open-source alternative to premium security solutions.

## Why I built this

I wanted to see if I could replace Zenarmor Premium (which costs money) with my own AI-based solution using Snort 3 and TensorFlow. The goal was to learn how zero-day detection works and have a real project in my portfolio.

## What I achieved

- Trained model with **100% accuracy** on 16,000 samples
- Complete scripts for data generation and training
- Model exported in `.h5` format (ready for Snort 3)
- Full documentation of the process

## How I did it

### 1. Generated the dataset

I created two categories of HTTP traffic:
- **Normal** (8000 samples) - legitimate requests (e.g., `id=123`, `q=laptop`)
- **SQL injection attacks** (8000 samples) - various techniques (tautology, union, stacked queries, time-based)

I extracted 15 features from each request:
- parameter length
- number of special characters
- number of `&` characters (multiple parameters)
- number of digits
- presence of SQL keywords (`'`, `or`, `and`, `select`, `union`, `drop`, `--`, `;`, `=`, `sleep`, `benchmark`)

### 2. Trained the model

I used a neural network with the following architecture:

- Input layer (15 features)
- Dense 64 + BatchNorm + Dropout 0.3
- Dense 32 + BatchNorm + Dropout 0.2
- Dense 16 + Dropout 0.2
- Dense 8
- Output (sigmoid)

Settings used:
- Optimizer: Adam (learning_rate=0.0005)
- Loss: binary_crossentropy
- EarlyStopping (patience 15 epochs)
- ReduceLROnPlateau to adjust learning rate

### 3. Results

On the test set (3200 samples):
- **Accuracy: 100%**
- **Precision: 100%**
- **Recall: 100%**

### 4. Problems encountered and solutions

| Problem | Solution |
|---------|----------|
| Initially, the model didn't detect attacks well | Added more attack types to the training set |
| A false positive appeared for `product=laptop&page=2` | Added normal requests with `&` and longer length to the training set |
| Installing TensorFlow on Ubuntu 24.04 | Used a virtual environment (`python3 -m venv`) |
| Snort 3 didn't have ML support compiled | Recompiled Snort with `--enable-ml` (separate process) |

## What I learned

1. **Machine Learning for security is not magic** - it needs quality data and careful feature engineering
2. **The dataset is key** - the more attack variants you add, the more robust the model becomes
3. **False positives are the biggest challenge** - I spent a lot of time eliminating them
4. **Integration with Snort 3 is possible but complex** - requires special compilation

## How to use this project

### Run data generation and training

# Generate the dataset
python3 generate_improved_dataset.py

# Train the model
python3 train_improved_model_v2.py
Use the model with Snort 3
Copy snort_model_improved.h5 to /usr/local/lib/

Compile Snort 3 with --enable-ml

Configure Snort to use the model

Requirements
bash
pip install tensorflow numpy scapy
Conclusion
This project demonstrates that you can build an SQL injection detection system using Machine Learning with minimal resources (laptop, VM, open-source software). The results are promising (100% accuracy in testing), and the model can be integrated into Snort 3 for real-time protection.

Author
Ilie Lucian
Technical Department Manager | Learning cybersecurity through hands-on projects

Project completed in April 2026 as part of my cybersecurity learning journey.
