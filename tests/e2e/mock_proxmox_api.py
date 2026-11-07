#!/usr/bin/env python3
"""In-memory, loopback-only HTTPS simulation of Proxmox's API-token endpoints.

This server never contacts Proxmox. Its credentials are fixed, non-sensitive CI
test fixtures. Do not expose its listener outside the runner.
"""
import argparse
import json
import re
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from urllib.parse import parse_qs, unquote, urlsplit

ISSUER_AUTH = "PVEAPIToken=issuer@pve!bootstrap=ci-only-issuer-secret"
ROUTE = re.compile(r"^/api2/json/access/users/([^/]+)/token/([^/]+)$")
TOKENS = {}
COUNTS = {"created": 0, "deleted": 0, "rejected": 0}
LOCK = Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        # Never log authorization headers, request bodies, or token secrets.
        pass

    def respond(self, code, payload):
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/__test__/state":
            with LOCK:
                self.respond(200, {
                    "created": COUNTS["created"],
                    "deleted": COUNTS["deleted"],
                    "rejected": COUNTS["rejected"],
                    "active": [
                        {"user": user, "token_id": token_id, "expire": item["expire"],
                         "privsep": item["privsep"]}
                        for (user, token_id), item in TOKENS.items()
                    ],
                })
            return
        if path == "/__test__/authenticate":
            header = self.headers.get("Authorization", "")
            with LOCK:
                valid = any(
                    header == f"PVEAPIToken={user}!{name}={item['secret']}"
                    and item["expire"] > time.time()
                    for (user, name), item in TOKENS.items()
                )
            self.respond(200 if valid else 401, {"authorized": valid})
            return
        self.respond(404, {"errors": "unknown route"})

    def do_POST(self):
        self.handle_token("POST")

    def do_DELETE(self):
        self.handle_token("DELETE")

    def handle_token(self, method):
        match = ROUTE.fullmatch(urlsplit(self.path).path)
        if not match:
            self.respond(404, {"errors": "unknown token path"})
            return
        user, token_id = map(unquote, match.groups())
        if self.headers.get("Authorization") != ISSUER_AUTH:
            self.respond(401, {"errors": "issuer authorization required"})
            return
        if user == "forbidden@pve":
            with LOCK:
                COUNTS["rejected"] += 1
            self.respond(403, {"errors": "simulated denied Proxmox permission"})
            return
        if user != "workload@pve":
            self.respond(403, {"errors": "issuer may only manage workload@pve"})
            return
        key = (user, token_id)
        if method == "DELETE":
            with LOCK:
                if key not in TOKENS:
                    self.respond(404, {"errors": "token not found"})
                    return
                del TOKENS[key]
                COUNTS["deleted"] += 1
            self.respond(200, {"data": None})
            return

        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 65536:
            self.respond(400, {"errors": "invalid body length"})
            return
        raw = self.rfile.read(length).decode("utf-8")
        # The Telmate Proxmox client sends form values. Decode the body
        # directly rather than relying on the Content-Type header.
        try:
            if raw.lstrip().startswith("{"):
                fields = json.loads(raw)
                get = lambda k: str(fields.get(k, ""))
            else:
                fields = parse_qs(raw, keep_blank_values=True)
                get = lambda k: fields.get(k, [""])[0]
            expiry = int(get("expire"))
            privilege_separation = get("privsep")
        except (ValueError, TypeError, json.JSONDecodeError):
            self.respond(400, {"errors": "invalid token configuration"})
            return
        if expiry <= time.time() or expiry > time.time() + 3600 or privilege_separation != "0":
            self.respond(400, {"errors": "unsafe token expiration or privilege settings"})
            return
        secret = "ci-only-generated-token-value"
        with LOCK:
            if key in TOKENS:
                self.respond(409, {"errors": "duplicate token ID"})
                return
            TOKENS[key] = {
                "secret": secret,
                "expire": expiry,
                "privsep": privilege_separation,
            }
            COUNTS["created"] += 1
        self.respond(200, {"data": {"value": secret}})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--port", type=int, default=8843)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(args.cert, args.key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print("Loopback-only Proxmox mock is ready", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
