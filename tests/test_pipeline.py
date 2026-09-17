import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from webapi_extractor.analyzer import analyze_capture
from webapi_extractor.auth import http_login
from webapi_extractor.generator import generate


class MockAuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/form":
            body = b'<form action="/signin"><input name="username"><input name="password"></form>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/":
            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path != "/signin":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode()
        if "alice" in body and "correct" in body:
            self.send_response(302)
            self.send_header("Set-Cookie", "sid=authenticated")
            self.send_header("Location", "/")
            self.end_headers()
        else:
            self.send_response(401)
            self.end_headers()

    def log_message(self, *_args):
        pass


@pytest.fixture
def mock_auth_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockAuthHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.mark.asyncio
async def test_http_form_login(mock_auth_server, tmp_path):
    result = await http_login(f"{mock_auth_server}/form", "alice", "correct", tmp_path)
    assert result["success"] is True
    assert result["token_type"] == "cookie"
    assert list(tmp_path.glob("*.json"))


def test_analyze_and_generate_pipeline(tmp_path):
    session = tmp_path / "session"
    session.mkdir()
    events = [
        {"type": "request", "requestId": "1", "method": "GET", "url": "https://api.example.com/orders/123", "headers": {}, "resourceType": "XHR"},
        {"type": "response", "requestId": "1", "status": 200, "headers": {}, "mimeType": "application/json"},
        {"type": "response_body", "requestId": "1", "body": '{"orderId":123,"state":"new"}'},
        {"type": "request", "requestId": "2", "method": "GET", "url": "https://api.example.com/orders/456", "headers": {}, "resourceType": "XHR"},
        {"type": "response", "requestId": "2", "status": 200, "headers": {}, "mimeType": "application/json"},
        {"type": "response_body", "requestId": "2", "body": '{"orderId":456,"state":"new"}'},
        {"type": "request", "requestId": "3", "method": "GET", "url": "https://api.example.com/orders/latest", "headers": {}, "resourceType": "XHR"},
        {"type": "response", "requestId": "3", "status": 200, "headers": {}, "mimeType": "application/json"},
        {"type": "response_body", "requestId": "3", "body": '{"orderId":999,"state":"new"}'},
    ]
    (session / "capture.jsonl").write_text("\n".join(json.dumps(event) for event in events), encoding="utf-8")
    analysis = analyze_capture(session)
    assert analysis["stats"]["unique"] == 2
    assert {endpoint["path"] for endpoint in analysis["endpoints"]} == {"/orders/{id}", "/orders/latest"}
    result = generate(session, tmp_path / "generated", ["ep_001"])
    assert result["endpoint_count"] == 1
    assert (tmp_path / "generated" / "server.py").exists()


def test_login_detector_marks_auth_ready_for_successful_login():
    from webapi_extractor.login_detector import detect_login_success

    result = detect_login_success(
        request_urls=[
            "https://example.com/login",
            "https://example.com/api/session",
            "https://example.com/api/profile",
        ],
        observed_headers={"Authorization": "Bearer token-123"},
        storage_state={"cookies": [{"name": "sessionid", "value": "abc"}]},
        session_storage={"token": "abc"},
    )

    assert result["status"] == "completed"
    assert result["auth_ready"] is True
    assert "authorization" in " ".join(result["evidence"]).lower()


def test_capture_session_starts_in_authenticating_until_login_ready():
    from webapi_extractor.capture import CaptureSession
    from webapi_extractor.storage import SessionStore

    store = SessionStore(__import__("pathlib").Path(".") / "tmp_capture_sessions")
    session = CaptureSession("demo_session", "https://example.com", store, 1024, 300, auth_state_path=None)

    assert session.status == "authenticating"
    session.auth_ready = True
    session.status = "capturing"
    assert session.status == "capturing"
    assert session.auth_ready is True