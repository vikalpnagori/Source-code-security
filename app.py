import json
from flask import Flask, render_template, jsonify

app = Flask(__name__)

# Function to load the enriched data from the JSON file
def load_scan_results():
    try:
        with open("final_results.json", 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

@app.route('/')
def dashboard():
    findings = load_scan_results()

    # Data for the summary chart
    risk_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }
    for finding in findings:
        score = finding.get('llm_risk_score', 'UNKNOWN').upper()
        if score in risk_counts:
            risk_counts[score] += 1
        else:
            risk_counts['LOW'] += 1 # Default to low if unknown

    chart_data = {
        "labels": list(risk_counts.keys()),
        "data": list(risk_counts.values())
    }

    return render_template('dashboard.html', findings=findings, chart_data=chart_data)

@app.route('/api/results')
def api_results():
    findings = load_scan_results()
    return jsonify(findings)

if __name__ == '__main__':
    # Running in debug mode for development. In production, use a WSGI server.
    app.run(host='0.0.0.0',debug=True)
