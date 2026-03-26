from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import sqlite3
import os
import json
import base64
import datetime
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

try:
    import jwt as pyjwt
except ImportError:
    pyjwt = None


class ExpiredSignatureError(Exception):
    pass


class InvalidSignatureError(Exception):
    pass


if pyjwt is not None:
    ExpiredSignatureError = getattr(pyjwt, 'ExpiredSignatureError', ExpiredSignatureError)
    InvalidSignatureError = getattr(pyjwt, 'InvalidSignatureError', InvalidSignatureError)

hostName = "localhost"
serverPort = 8080
DATABASE_FILE = "totally_not_my_privateKeys.db"
MOCK_USERNAME = "userABC"
MOCK_PASSWORD = "password123"


def init_db(db_path=DATABASE_FILE):
    if db_path and os.path.dirname(db_path):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key(key_bytes):
    return serialization.load_pem_private_key(key_bytes, password=None, backend=default_backend())


def store_key(conn, key_pem, exp):
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key_pem, exp))
    conn.commit()
    return cursor.lastrowid


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def base64url_decode(data: str) -> bytes:
    padding_needed = 4 - (len(data) % 4)
    if padding_needed and padding_needed != 4:
        data += '=' * padding_needed
    return base64.urlsafe_b64decode(data.encode('utf-8'))


def get_unverified_header(token: str) -> dict:
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError('Invalid JWT format')
    header_bytes = base64url_decode(parts[0])
    return json.loads(header_bytes.decode('utf-8'))


def jwt_encode(payload: dict, private_key, headers: dict = None) -> str:
    if pyjwt is not None and hasattr(pyjwt, 'encode'):
        return pyjwt.encode(payload, private_key, algorithm='RS256', headers=headers or {})

    jwt_header = {'typ': 'JWT', 'alg': 'RS256'}
    if headers:
        jwt_header.update(headers)

    header_b = json.dumps(jwt_header, separators=(',', ':')).encode('utf-8')
    payload_b = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    encoded_header = base64url_encode(header_b)
    encoded_payload = base64url_encode(payload_b)
    signing_input = f"{encoded_header}.{encoded_payload}".encode('utf-8')

    signature = private_key.sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    encoded_signature = base64url_encode(signature)
    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"


def jwt_decode(token: str, public_key, verify_exp: bool = True) -> dict:
    if pyjwt is not None and hasattr(pyjwt, 'decode'):
        return pyjwt.decode(token, public_key, algorithms=['RS256'])

    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError('Invalid JWT format')

    header_b = base64url_decode(parts[0])
    payload_b = base64url_decode(parts[1])
    signature = base64url_decode(parts[2])
    signing_input = f"{parts[0]}.{parts[1]}".encode('utf-8')

    try:
        public_key.verify(
            signature,
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception as exc:
        raise InvalidSignatureError('Invalid signature') from exc

    payload = json.loads(payload_b.decode('utf-8'))
    if verify_exp:
        exp = payload.get('exp')
        if exp is not None and int(time.time()) > int(exp):
            raise ExpiredSignatureError('Expired token')

    return payload


def get_key(conn, expired=False):
    now = int(time.time())
    cursor = conn.cursor()
    if expired:
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
            (now,),
        )
    else:
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp >= ? ORDER BY exp ASC LIMIT 1",
            (now,),
        )
    return cursor.fetchone()


def generate_and_store_keys(conn):
    now = int(time.time())
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM keys WHERE exp <= ?", (now,))
    expired_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM keys WHERE exp >= ?", (now + 3600,))
    valid_count = cursor.fetchone()[0]

    if expired_count == 0:
        expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        expired_pem = serialize_private_key(expired_key)
        store_key(conn, expired_pem, now - 3600)

    if valid_count == 0:
        valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        valid_pem = serialize_private_key(valid_key)
        store_key(conn, valid_pem, now + 7200)


def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


def private_key_to_jwk(key_bytes, kid):
    private_key = load_private_key(key_bytes)
    public_numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": str(kid),
        "n": int_to_base64(public_numbers.n),
        "e": int_to_base64(public_numbers.e),
    }


def build_jwks(conn):
    now = int(time.time())
    cursor = conn.cursor()
    cursor.execute("SELECT kid, key, exp FROM keys WHERE exp >= ?", (now,))
    rows = cursor.fetchall()
    return {"keys": [private_key_to_jwk(row[1], row[0]) for row in rows]}


def sign_jwt(conn, expired=False):
    row = get_key(conn, expired=expired)
    if not row:
        return None

    kid, key_blob, key_exp = row
    private_key = load_private_key(key_blob)
    payload = {
        "username": MOCK_USERNAME,
        "exp": key_exp,
    }
    headers = {"kid": str(kid)}
    token = jwt_encode(payload, private_key, headers=headers)
    return token


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path != "/auth":
            self.send_response(405)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""

        try:
            credentials = json.loads(body.decode("utf-8"))
        except Exception:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid JSON")
            return

        if (
            credentials.get("username") != MOCK_USERNAME
            or credentials.get("password") != MOCK_PASSWORD
        ):
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"Unauthorized")
            return

        expired = params.get("expired", ["false"])[0].lower() == "true"

        conn = init_db(DATABASE_FILE)
        try:
            token = sign_jwt(conn, expired=expired)
            if token is None:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Key not found")
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(token.encode("utf-8") if isinstance(token, str) else token)
        finally:
            conn.close()

    def do_GET(self):
        if self.path != "/.well-known/jwks.json":
            self.send_response(405)
            self.end_headers()
            return

        conn = init_db(DATABASE_FILE)
        try:
            jwks = build_jwks(conn)
        finally:
            conn.close()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(jwks).encode("utf-8"))


if __name__ == "__main__":
    conn = init_db(DATABASE_FILE)
    try:
        generate_and_store_keys(conn)
    finally:
        conn.close()

    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        webServer.server_close()

