#!/usr/bin/env python3
"""
Dashboard - Interfata web pentru monitorizarea atacurilor in timp real
"""

from flask import Flask, jsonify, render_template_string, request
import threading
from datetime import datetime

app = Flask(__name__)

events = []
stats = {
    "total": 0,
    "malicious": 0,
    "normal": 0,
    "last_attack": None
}
lock = threading.Lock()

HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>SnortML Dashboard</title>
    <meta charset="utf-8">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0a0a0a; color: #00ff41; font-family: monospace; padding: 20px; }
        h1 { text-align: center; font-size: 2em; margin-bottom: 10px; color: #00ff41; text-shadow: 0 0 10px #00ff41; }
        .subtitle { text-align: center; color: #666; margin-bottom: 30px; }
        .stats { display: flex; gap: 20px; margin-bottom: 30px; justify-content: center; }
        .stat-box { background: #111; border: 1px solid #00ff41; padding: 20px 40px; text-align: center; border-radius: 4px; }
        .stat-box.danger { border-color: #ff0040; }
        .stat-number { font-size: 2.5em; font-weight: bold; }
        .stat-number.red { color: #ff0040; }
        .stat-number.green { color: #00ff41; }
        .stat-label { color: #666; font-size: 0.9em; margin-top: 5px; }
        .section-title { color: #666; margin-bottom: 10px; font-size: 0.9em; letter-spacing: 2px; }
        table { width: 100%; border-collapse: collapse; background: #111; }
        th { background: #1a1a1a; padding: 10px; text-align: left; color: #666; font-size: 0.8em; letter-spacing: 1px; border-bottom: 1px solid #222; }
        td { padding: 10px; border-bottom: 1px solid #1a1a1a; font-size: 0.85em; }
        .badge-block { color: #ff0040; font-weight: bold; }
        .badge-allow { color: #00ff41; }
        .score-bar { background: #1a1a1a; height: 6px; border-radius: 3px; margin-top: 4px; }
        .score-fill { height: 6px; border-radius: 3px; }
        .ip { color: #888; }
        .status { text-align: center; color: #333; font-size: 0.8em; margin-top: 20px; }
        .pulse { animation: pulse 2s infinite; }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
    </style>
</head>
<body>
    <h1>⚡ SnortML Security Dashboard</h1>
    <p class="subtitle">Real-time SQL Injection Detection powered by TensorFlow</p>

    <div class="stats">
        <div class="stat-box">
            <div class="stat-number" id="total">0</div>
            <div class="stat-label">TOTAL REQUESTS</div>
        </div>
        <div class="stat-box danger">
            <div class="stat-number red" id="malicious">0</div>
            <div class="stat-label">ATTACKS BLOCKED</div>
        </div>
        <div class="stat-box">
            <div class="stat-number green" id="normal">0</div>
            <div class="stat-label">NORMAL REQUESTS</div>
        </div>
    </div>

    <p class="section-title">▶ LIVE EVENT LOG</p>
    <table>
        <thead>
            <tr>
                <th>TIME</th>
                <th>SOURCE IP</th>
                <th>PARAMETER</th>
                <th>SCORE</th>
                <th>VERDICT</th>
            </tr>
        </thead>
        <tbody id="events-body">
            <tr><td colspan="5" style="text-align:center;color:#333;">Waiting for traffic...</td></tr>
        </tbody>
    </table>

    <p class="status pulse" id="status">● MONITORING ACTIVE</p>

    <script>
        function update() {
            fetch('/api/data')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('total').textContent = data.stats.total;
                    document.getElementById('malicious').textContent = data.stats.malicious;
                    document.getElementById('normal').textContent = data.stats.normal;

                    const tbody = document.getElementById('events-body');
                    if (data.events.length === 0) return;

                    tbody.innerHTML = data.events.slice().reverse().map(e => `
                        <tr>
                            <td>${e.time}</td>
                            <td class="ip">${e.src_ip}</td>
                            <td>${e.param.substring(0, 50)}${e.param.length > 50 ? '...' : ''}</td>
                            <td>
                                ${(e.score * 100).toFixed(1)}%
                                <div class="score-bar">
                                    <div class="score-fill" style="width:${e.score*100}%;background:${e.malicious ? '#ff0040' : '#00ff41'}"></div>
                                </div>
                            </td>
                            <td class="${e.malicious ? 'badge-block' : 'badge-allow'}">${e.verdict}</td>
                        </tr>
                    `).join('');
                });
        }
        update();
        setInterval(update, 2000);
    </script>
</body>
</html>
'''

@app.route('/')
def dashboard():
    return render_template_string(HTML)

@app.route('/api/data')
def api_data():
    with lock:
        return jsonify({
            "stats": stats.copy(),
            "events": events[-50:]
        })

@app.route('/api/event', methods=['POST'])
def add_event():
    data = request.get_json()
    with lock:
        events.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "src_ip": data.get("src_ip", "unknown"),
            "param": data.get("param", ""),
            "score": data.get("score", 0),
            "malicious": data.get("malicious", False),
            "verdict": "BLOCK" if data.get("malicious") else "ALLOW"
        })
        stats["total"] += 1
        if data.get("malicious"):
            stats["malicious"] += 1
            stats["last_attack"] = datetime.now().strftime("%H:%M:%S")
        else:
            stats["normal"] += 1
    return jsonify({"ok": True})

if __name__ == '__main__':
    print("Dashboard pornit pe http://0.0.0.0:8080")
    app.run(host='0.0.0.0', port=8080, debug=False)
