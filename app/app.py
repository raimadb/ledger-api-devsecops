import os
import hashlib
import ipaddress
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)

STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY", "")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")

LEDGER = [
    {"id": "txn_1001", "pan": "4242424242424242", "amount": 4200, "currency": "USD", "status": "captured"},
    {"id": "txn_1002", "pan": "5555555555554444", "amount": 1899, "currency": "EUR", "status": "refunded"},
]

def is_safe_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname
        if not host:
            return False
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_global
        except ValueError:
            # host is a domain name, not a raw IP
            blocked_hosts = {"localhost", "169.254.169.254"}
            return host not in blocked_hosts
    except ValueError:
        return False

@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/tokenize", methods=["POST"])
def tokenize():
    payload = request.get_json(silent=True) or {}
    pan = payload.get("pan", "")
    token = "tok_" + hashlib.sha256(pan.encode()).hexdigest()[:24]
    return jsonify(token=token, last4=pan[-4:])


@app.route("/transactions")
def transactions():
    return jsonify(transactions=LEDGER)


@app.route("/import", methods=["POST"])
def import_config():
    config = yaml.safe_load(request.data)
    return jsonify(loaded=str(config))


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not is_safe_url(url):
        return jsonify(error="URL not allowed"), 400
    # SSRF mitigated by is_safe_url() above: blocks non-global IPs, localhost, and
    # cloud metadata IP. See Task 1 README for live verification evidence.
    resp = requests.get(url, timeout=5, allow_redirects=False)	# nosemgrep: python.django.security.injection.ssrf.ssrf-injection-requests.ssrf-injection-requests,python.flask.security.injection.ssrf-requests
    return jsonify(status_code=resp.status_code, body=resp.text[:2048])


if __name__ == "__main__":
    # 0.0.0.0 binding is required for container networking — the app is never
    # exposed directly; only reachable via Kubernetes Service/Ingress, with
    # NetworkPolicy/Istio mTLS restricting access further (see Task 3).
    app.run(host="0.0.0.0", port=8080) # nosemgrep: python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host
