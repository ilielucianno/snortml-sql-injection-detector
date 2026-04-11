#!/usr/bin/env python3
"""
Snort Bridge - Captureaza trafic HTTP si trimite la ML Service
"""

from scapy.all import sniff, TCP, IP, Raw
import requests
import re
import logging
from urllib.parse import unquote, parse_qs

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

ML_SERVICE = "http://127.0.0.1:5000/predict"
DASHBOARD = "http://127.0.0.1:8080/api/event"

def extract_http_params(payload):
    try:
        payload_str = payload.decode('utf-8', errors='ignore')
        get_match = re.search(r'GET\s+[^\s]*\?([^\s&HTTP]+(?:&[^\s&HTTP]+)*)', payload_str)
        if get_match:
            return get_match.group(1)
        if 'POST' in payload_str:
            parts = payload_str.split('\r\n\r\n')
            if len(parts) > 1:
                return parts[1].strip()
        return None
    except Exception as e:
        logger.error(f"Eroare la extragerea parametrilor: {e}")
        return None

def check_with_ml(param):
    try:
        response = requests.post(
            ML_SERVICE,
            json={"param": param},
            timeout=2
        )
        return response.json()
    except Exception as e:
        logger.error(f"Eroare la ML service: {e}")
        return None

def process_packet(packet):
    if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
        return
    payload = bytes(packet[Raw].load)
    if not (b'GET' in payload or b'POST' in payload):
        return
    params = extract_http_params(payload)
    if not params:
        return
    result = check_with_ml(params)
    if not result:
        return
    src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
    try:
        requests.post(DASHBOARD, json={
            "src_ip": src_ip,
            "param": params,
            "score": result.get("score", 0),
            "malicious": result.get("malicious", False)
        }, timeout=1)
    except:
        pass
    if result.get("malicious"):
        logger.warning(f"SQL INJECTION DETECTAT!")
        logger.warning(f"   Sursa: {src_ip}")
        logger.warning(f"   Param: {params}")
        logger.warning(f"   Score: {result.get('score', 0):.4f}")
        logger.warning(f"   Verdict: BLOCK")
    else:
        logger.info(f"NORMAL | {src_ip} | {params[:50]}")

if __name__ == '__main__':
    logger.info("Snort ML Bridge pornit!")
    logger.info(f"ML Service: {ML_SERVICE}")
    logger.info("Ascultam trafic HTTP pe portul 80...")
    logger.info("Apasa Ctrl+C pentru a opri\n")
    sniff(
        filter="tcp port 80",
        prn=process_packet,
        store=0,
        iface="enp0s3"
    )
