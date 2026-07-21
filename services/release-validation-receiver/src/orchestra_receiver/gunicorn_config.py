from __future__ import annotations

import os
import ssl

bind = os.environ.get("RECEIVER_BIND", "0.0.0.0:8080")
workers = int(os.environ.get("RECEIVER_API_WORKERS", "2"))
threads = int(os.environ.get("RECEIVER_API_THREADS", "4"))
worker_class = "gthread"
accesslog = "-"
errorlog = "-"
graceful_timeout = 30
timeout = 30

certfile = os.environ.get("RECEIVER_TLS_CERTIFICATE_FILE")
keyfile = os.environ.get("RECEIVER_TLS_PRIVATE_KEY_FILE")
ca_certs = os.environ.get("RECEIVER_TLS_CLIENT_CA_FILE")

if bool(certfile) != bool(keyfile):
    raise RuntimeError(
        "receiver server TLS requires both certificate and private key files"
    )
if ca_certs and not certfile:
    raise RuntimeError("receiver client CA requires server TLS")
cert_reqs = ssl.CERT_REQUIRED if ca_certs else ssl.CERT_NONE
