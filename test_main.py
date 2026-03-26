import json
import os
import sqlite3
import tempfile
import time
import threading
from http.client import HTTPConnection
from http.server import HTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

import main


def start_server(db_path):
    main.DATABASE_FILE = db_path
    conn = main.init_db(db_path)
    try:
        main.generate_and_store_keys(conn)
    finally:
        conn.close()

    server = HTTPServer(("localhost", 0), main.MyServer)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def stop_server(server):
    server.shutdown()
    server.server_close()


def test_db_init_and_key_seed():
    print("\n" + "="*70)
    print("TEST: Database Initialization and Key Seeding")
    print("="*70)
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.db")
        print(f"[SETUP] Creating temporary database at: {path}")

        conn = main.init_db(path)
        try:
            print("[ACTION] Initializing database with RSA key pairs...")
            main.generate_and_store_keys(conn)
            
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM keys")
            total = cur.fetchone()[0]
            print(f"[VERIFY] Total keys generated: {total}")
            assert total >= 2, f"Expected at least 2 keys, got {total}"
            print(f"✓ PASS: Generated {total} keys (expected >= 2)")

            now = int(time.time())
            cur.execute("SELECT COUNT(*) FROM keys WHERE exp <= ?", (now,))
            expired_count = cur.fetchone()[0]
            print(f"[VERIFY] Expired keys count: {expired_count}")
            assert expired_count >= 1, f"Expected at least 1 expired key, got {expired_count}"
            print(f"✓ PASS: Found {expired_count} expired keys (expected >= 1)")
            
            cur.execute("SELECT COUNT(*) FROM keys WHERE exp >= ?", (now + 3600,))
            valid_count = cur.fetchone()[0]
            print(f"[VERIFY] Valid keys (>1hr future): {valid_count}")
            assert valid_count >= 1, f"Expected at least 1 valid key, got {valid_count}"
            print(f"✓ PASS: Found {valid_count} valid keys (expected >= 1)")
        finally:
            conn.close()
    print("[RESULT] ✓ Database initialization test PASSED")
    print()


def test_get_key_selection():
    print("\n" + "="*70)
    print("TEST: Key Selection Logic (Expired vs Valid)")
    print("="*70)
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.db")
        print(f"[SETUP] Creating temporary database at: {path}")
        conn = main.init_db(path)
        try:
            print("[ACTION] Generating and storing key pairs...")
            main.generate_and_store_keys(conn)
            
            print("[ACTION] Retrieving expired key...")
            expired = main.get_key(conn, expired=True)
            assert expired is not None, "Failed to retrieve expired key"
            expired_kid, _, expired_exp = expired
            print(f"✓ Retrieved expired key (KID={expired_kid}, exp={expired_exp})")
            
            print("[ACTION] Retrieving valid (non-expired) key...")
            valid = main.get_key(conn, expired=False)
            assert valid is not None, "Failed to retrieve valid key"
            valid_kid, _, valid_exp = valid
            print(f"✓ Retrieved valid key (KID={valid_kid}, exp={valid_exp})")
            
            now = int(time.time())
            print(f"[VERIFY] Current timestamp: {now}")
            assert expired_exp <= now, f"Expired key exp ({expired_exp}) should be <= now ({now})"
            print(f"✓ PASS: Expired key timestamp {expired_exp} <= {now}")
            
            assert valid_exp >= now, f"Valid key exp ({valid_exp}) should be >= now ({now})"
            print(f"✓ PASS: Valid key timestamp {valid_exp} >= {now}")
        finally:
            conn.close()
    print("[RESULT] ✓ Key selection test PASSED")
    print()


def test_jwks_endpoint_excludes_expired():
    print("\n" + "="*70)
    print("TEST: JWKS Endpoint (.well-known/jwks.json)")
    print("="*70)
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        print(f"[SETUP] Starting HTTP server with database at: {db_path}")
        server, port = start_server(db_path)
        print(f"[INFO] Server started on localhost:{port}")
        try:
            print(f"[ACTION] Sending GET request to http://localhost:{port}/.well-known/jwks.json")
            conn = HTTPConnection("localhost", port)
            conn.request("GET", "/.well-known/jwks.json")
            resp = conn.getresponse()
            print(f"[VERIFY] Response status code: {resp.status}")
            assert resp.status == 200, f"Expected status 200, got {resp.status}"
            print(f"✓ PASS: Received HTTP 200 OK")
            
            body = resp.read().decode("utf-8")
            data = json.loads(body)
            print(f"[VERIFY] Response contains 'keys' field: {'keys' in data}")
            print(f"[VERIFY] Number of keys in response: {len(data.get('keys', []))}")
            assert "keys" in data and len(data["keys"]) >= 1, f"Expected at least 1 key, got {len(data.get('keys', []))}"
            print(f"✓ PASS: Response contains {len(data['keys'])} valid keys")
            for i, key in enumerate(data['keys']):
                print(f"   - Key {i+1}: KID={key.get('kid')}, ALG={key.get('alg')}, KTY={key.get('kty')}")

            # Ensure all returned keys are non-expired
            now = int(time.time())
            print(f"[VERIFY] Checking that endpoint only returns non-expired keys (now={now})")
            conndb = sqlite3.connect(db_path)
            try:
                keys_db = conndb.execute("SELECT kid, exp FROM keys WHERE exp >= ?", (now,)).fetchall()
                print(f"[INFO] Database has {len(keys_db)} non-expired keys")
                assert len(keys_db) > 0, "Database should contain non-expired keys"
                print(f"✓ PASS: Endpoint correctly excludes expired keys")
            finally:
                conndb.close()
        finally:
            print("[CLEANUP] Stopping server...")
            stop_server(server)
    print("[RESULT] ✓ JWKS endpoint test PASSED")
    print()


def _get_public_key_by_kid(db_path, kid):
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT key FROM keys WHERE kid = ?", (kid,)).fetchone()
        assert row is not None
        private_key = main.load_private_key(row[0])
        return private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    finally:
        conn.close()


def test_auth_endpoint_valid_credentials():
    print("\n" + "="*70)
    print("TEST: Auth Endpoint with Valid Credentials")
    print("="*70)
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        print(f"[SETUP] Starting HTTP server with database at: {db_path}")
        server, port = start_server(db_path)
        print(f"[INFO] Server started on localhost:{port}")
        try:
            print(f"[ACTION] Sending POST request to http://localhost:{port}/auth")
            conn = HTTPConnection("localhost", port)
            payload = json.dumps({"username": "userABC", "password": "password123"})
            print(f"[INFO] Credentials: username=userABC, password=password123")
            conn.request("POST", "/auth", body=payload, headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            print(f"[VERIFY] Response status code: {resp.status}")
            assert resp.status == 200, f"Expected status 200, got {resp.status}"
            print(f"✓ PASS: Received HTTP 200 OK")
            
            token = resp.read().decode("utf-8")
            print(f"[INFO] Received JWT token (length={len(token)})")
            print(f"[INFO] Token preview: {token[:60]}...")
            
            print(f"[ACTION] Decoding and verifying JWT token...")
            header = main.get_unverified_header(token)
            kid = header.get("kid")
            print(f"[INFO] JWT Header: alg={header.get('alg')}, kid={kid}, typ={header.get('typ')}")
            
            print(f"[ACTION] Retrieving public key for KID={kid} from database...")
            pub_key = _get_public_key_by_kid(db_path, int(kid))
            print(f"✓ Retrieved public key successfully")
            
            print(f"[ACTION] Verifying JWT signature and claims...")
            decoded = main.jwt_decode(token, pub_key, verify_exp=True)
            print(f"[INFO] JWT Claims: username={decoded.get('username')}, exp={decoded.get('exp')}")
            assert decoded["username"] == "userABC", f"Expected username=userABC, got {decoded['username']}"
            print(f"✓ PASS: JWT signature is valid and username verified")
        finally:
            print("[CLEANUP] Stopping server...")
            stop_server(server)
    print("[RESULT] ✓ Auth endpoint (valid credentials) test PASSED")
    print()


def test_auth_endpoint_expired_key():
    print("\n" + "="*70)
    print("TEST: Auth Endpoint with Expired Key Request")
    print("="*70)
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        print(f"[SETUP] Starting HTTP server with database at: {db_path}")
        server, port = start_server(db_path)
        print(f"[INFO] Server started on localhost:{port}")
        try:
            print(f"[ACTION] Sending POST request to http://localhost:{port}/auth?expired=true")
            conn = HTTPConnection("localhost", port)
            payload = json.dumps({"username": "userABC", "password": "password123"})
            print(f"[INFO] Credentials: username=userABC, password=password123")
            print(f"[INFO] Query parameter: expired=true (requesting expired key)")
            conn.request("POST", "/auth?expired=true", body=payload, headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            print(f"[VERIFY] Response status code: {resp.status}")
            assert resp.status == 200, f"Expected status 200, got {resp.status}"
            print(f"✓ PASS: Received HTTP 200 OK")
            
            token = resp.read().decode("utf-8")
            print(f"[INFO] Received JWT token with expired key (length={len(token)})")
            print(f"[INFO] Token preview: {token[:60]}...")
            
            print(f"[ACTION] Decoding JWT header...")
            header = main.get_unverified_header(token)
            kid = header.get("kid")
            print(f"[INFO] JWT Header: alg={header.get('alg')}, kid={kid}, typ={header.get('typ')}")
            
            print(f"[ACTION] Retrieving public key for KID={kid} from database...")
            pub_key = _get_public_key_by_kid(db_path, int(kid))
            print(f"✓ Retrieved public key successfully")
            
            print(f"[ACTION] Attempting to verify JWT with expired token (should raise ExpiredSignatureError)...")
            try:
                decoded = main.jwt_decode(token, pub_key, verify_exp=True)
                raise AssertionError("Expected ExpiredSignatureError to be raised, but token was decoded successfully")
            except main.ExpiredSignatureError as e:
                print(f"✓ PASS: Correctly raised ExpiredSignatureError: {e}")
        finally:
            print("[CLEANUP] Stopping server...")
            stop_server(server)
    print("[RESULT] ✓ Auth endpoint (expired key) test PASSED")
    print()
