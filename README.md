# SnortML SQL Injection Detector

Machine Learning based SQL injection detection for Snort 3 using TensorFlow.

## Overview

This project demonstrates how to train a neural network model to detect SQL injection attacks. The model achieves **100% accuracy** on a test dataset of 3,200 samples.

## Model Architecture

- Input layer (15 features)
- Dense 64 + BatchNorm + Dropout 0.3
- Dense 32 + BatchNorm + Dropout 0.2
- Dense 16 + Dropout 0.2
- Dense 8
- Output (sigmoid)

## Results

| Metric | Value |
|--------|-------|
| Test Accuracy | 100% |
| Test Precision | 100% |
| Test Recall | 100% |

## Files

- `generate_improved_dataset.py` - Generates training data
- `train_improved_model_v2.py` - Trains the model
- `snort_model_improved.h5` - Trained model for Snort 3

## Requirements

```bash
pip install tensorflow numpy scapy
Author
Ilie Lucian
