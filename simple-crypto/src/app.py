#!/usr/bin/env python3
import hashlib
from pathlib import Path

from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

KEY = hashlib.sha256(b"simple-crypto-fixed-stream").digest()
FLAG_PATH = Path("/flag")

PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Simple Crypto</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      font-family: system-ui, sans-serif;
      background: #f7f5ef;
      color: #201b12;
    }
    main {
      width: min(720px, calc(100vw - 32px));
    }
    h1 {
      font-size: 28px;
      margin: 0 0 12px;
    }
    code, pre {
      background: #ece6d8;
      border-radius: 6px;
    }
    code {
      padding: 2px 5px;
    }
    pre {
      overflow-x: auto;
      padding: 12px;
    }
  </style>
</head>
<body>
  <main>
    <h1>Encryption Oracle</h1>
    <p>The flag has already been encrypted. You can also encrypt your own messages.</p>
    <p><code>GET /api/flag</code></p>
    <p><code>POST /api/encrypt</code> with JSON <code>{"message":"hello"}</code></p>
    <pre>{{ flag_ciphertext }}</pre>
  </main>
</body>
</html>"""


def _stream_xor(data):
    return bytes(byte ^ KEY[index % len(KEY)] for index, byte in enumerate(data))


def _flag():
    return FLAG_PATH.read_bytes().strip()


@app.get("/")
def index():
    return render_template_string(PAGE, flag_ciphertext=_stream_xor(_flag()).hex())


@app.get("/api/flag")
def encrypted_flag():
    return jsonify(ciphertext=_stream_xor(_flag()).hex())


@app.post("/api/encrypt")
def encrypt():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "")
    if not isinstance(message, str):
        return jsonify(error="message must be a string"), 400
    raw = message.encode()
    if len(raw) > 512:
        return jsonify(error="message too long"), 400
    return jsonify(ciphertext=_stream_xor(raw).hex())


@app.get("/health")
def health():
    return "ok\n", 200, {"Content-Type": "text/plain"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8082)
