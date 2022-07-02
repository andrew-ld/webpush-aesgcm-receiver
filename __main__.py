import argparse
import http.server
import json
import logging
import os
import pprint
import ssl
import typing
import urllib.parse
import base64

import http_ece
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def main(ssl_ca: str, ssl_key: str, server_name: str, listen_host: str, listen_port: int) -> typing.NoReturn:
    token = os.urandom(16).hex()
    print("endpoint:", f"https://{server_name}/{token}")

    auth_secret = os.urandom(16)
    print("auth:", base64.urlsafe_b64encode(auth_secret).decode())

    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    public_key_raw = public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    print("p256dh:", base64.urlsafe_b64encode(public_key_raw).decode())

    class WebPushRequestHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path[1:] != token:
                return

            encrypted_body = self.rfile.read()

            salt = urllib.parse.parse_qs(self.headers["Encryption"]).get("salt")[0]
            salt = base64.urlsafe_b64decode(salt + ("=" * (len(salt) % 4)))

            remote_dh_seq = urllib.parse.parse_qs(self.headers["Crypto-Key"]).get("dh")[0]
            remote_dh_seq = base64.urlsafe_b64decode(remote_dh_seq + ("=" * (len(remote_dh_seq) % 4)))

            decrypted_body = http_ece.decrypt(
                content=encrypted_body,
                salt=salt,
                key=public_key_raw,
                auth_secret=auth_secret,
                version="aesgcm",
                private_key=private_key,
                dh=remote_dh_seq,
            )

            pprint.pprint(json.loads(decrypted_body))

            self.send_response(201)
            self.end_headers()

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(ssl_ca, ssl_key)

    httpd = http.server.HTTPServer((listen_host, listen_port), WebPushRequestHandler)
    httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)
    httpd.server_name = server_name
    httpd.serve_forever()


if __name__ == "__main__":
    logging.getLogger().setLevel(level=logging.ERROR)

    _parser = argparse.ArgumentParser()
    _parser.add_argument("--ssl-ca", type=str, required=True)
    _parser.add_argument("--ssl-key", type=str, required=True)
    _parser.add_argument("--server-name", type=str, required=True)
    _parser.add_argument("--listen-host", type=str, required=False, default="0.0.0.0")
    _parser.add_argument("--listen-port", type=int, required=False, default=443)

    _args = _parser.parse_args()
    main(_args.ssl_ca, _args.ssl_key, _args.server_name, _args.listen_host, _args.listen_port)
