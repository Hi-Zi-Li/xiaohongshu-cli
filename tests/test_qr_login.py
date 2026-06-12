"""Unit tests for QR code login flow."""

import sys
import types

import pytest

from xhs_cli.command_normalizers import normalize_xhs_user_payload
from xhs_cli.exceptions import XhsApiError
from xhs_cli.qr_login import BrowserQrLoginUnavailable, _normalize_browser_cookies, qrcode_login


class _FakeQrClient:
    instances = []

    def __init__(self, cookies, request_delay=0, **kwargs):
        self.cookies = dict(cookies)
        self.activate_calls = 0
        self.status_calls = 0
        self.complete_calls = 0
        self.create_seen_web_session = None
        self.status_seen_web_session = None
        self.complete_seen_web_sessions = []
        self.self_info_calls = 0
        type(self).instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def login_activate(self):
        self.activate_calls += 1
        if self.activate_calls == 1:
            return {"session": "guest-session", "secure_session": "guest-sec", "user_id": "guest-user"}
        return {"session": "unexpected-session", "secure_session": "unexpected-sec", "user_id": "unexpected-user"}

    def create_qr_login(self):
        self.create_seen_web_session = self.cookies.get("web_session")
        return {"qr_id": "qr-1", "code": "code-1", "url": "https://example.com/qr"}

    def check_qr_status(self, qr_id, code):
        self.status_calls += 1
        self.status_seen_web_session = self.cookies.get("web_session")
        return {"codeStatus": 2, "userId": "real-user"}

    def complete_qr_login(self, qr_id, code):
        self.complete_calls += 1
        self.complete_seen_web_sessions.append(self.cookies.get("web_session"))
        self.cookies["a1"] = "real-a1"
        self.cookies["webId"] = "real-webid"
        self.cookies["web_session"] = "real-session"
        self.cookies["web_session_sec"] = "real-sec"
        self.cookies["id_token"] = "real-id-token"
        return {
            "code_status": 2,
            "login_info": {
                "user_id": "real-user",
                "session": "real-session",
                "secure_session": "real-sec",
            },
        }

    def get_self_info(self):
        self.self_info_calls += 1
        return {
            "user_id": "real-user",
            "basic_info": {
                "user_id": "real-user",
                "nickname": "Alice",
                "red_id": "alice001",
            },
        }


class _MismatchQrClient(_FakeQrClient):
    def complete_qr_login(self, qr_id, code):
        self.complete_calls += 1
        self.complete_seen_web_sessions.append(self.cookies.get("web_session"))
        self.cookies["web_session"] = "wrong-session"
        self.cookies["web_session_sec"] = "wrong-sec"
        return {
            "code_status": 2,
            "login_info": {
                "user_id": "guest-user",
                "session": "wrong-session",
                "secure_session": "wrong-sec",
            },
        }

    def get_self_info(self):
        self.self_info_calls += 1
        return {
            "user_id": "guest-user",
            "basic_info": {
                "user_id": "guest-user",
                "nickname": "Guest",
                "red_id": "",
            },
        }


class _SelfInfoFallbackQrClient(_FakeQrClient):
    def complete_qr_login(self, qr_id, code):
        self.complete_calls += 1
        self.complete_seen_web_sessions.append(self.cookies.get("web_session"))
        self.cookies["a1"] = "real-a1"
        self.cookies["webId"] = "real-webid"
        self.cookies["web_session"] = "real-session"
        self.cookies["web_session_sec"] = "real-sec"
        self.cookies["id_token"] = "real-id-token"
        return {
            "code_status": 2,
            "login_info": {
                "user_id": "guest-user",
                "session": "real-session",
                "secure_session": "real-sec",
            },
        }


def test_qrcode_login_completes_after_confirmation_and_saves_real_session(monkeypatch):
    saved = []

    monkeypatch.setattr("xhs_cli.qr_login.XhsClient", _FakeQrClient)
    monkeypatch.setattr("xhs_cli.qr_login._generate_a1", lambda: "a1-fixed")
    monkeypatch.setattr("xhs_cli.qr_login._generate_webid", lambda: "webid-fixed")
    monkeypatch.setattr("xhs_cli.qr_login._display_qr_in_terminal", lambda data: True)
    monkeypatch.setattr("xhs_cli.qr_login.time.sleep", lambda seconds: None)
    monkeypatch.setattr("xhs_cli.qr_login.save_cookies", lambda cookies: saved.append(cookies))

    cookies = qrcode_login(timeout_s=1)
    client = _FakeQrClient.instances[-1]

    assert client.create_seen_web_session == "guest-session"
    assert client.status_seen_web_session == "guest-session"
    assert client.activate_calls == 1
    assert client.complete_calls == 1
    assert client.complete_seen_web_sessions == ["guest-session"]
    assert cookies == {
        "a1": "real-a1",
        "webId": "real-webid",
        "id_token": "real-id-token",
        "web_session": "real-session",
        "web_session_sec": "real-sec",
    }
    assert saved == [cookies]


def test_qrcode_login_accepts_confirmed_user_from_self_info_fallback(monkeypatch):
    saved = []

    monkeypatch.setattr("xhs_cli.qr_login.XhsClient", _SelfInfoFallbackQrClient)
    monkeypatch.setattr("xhs_cli.qr_login._generate_a1", lambda: "a1-fixed")
    monkeypatch.setattr("xhs_cli.qr_login._generate_webid", lambda: "webid-fixed")
    monkeypatch.setattr("xhs_cli.qr_login._display_qr_in_terminal", lambda data: True)
    monkeypatch.setattr("xhs_cli.qr_login.time.sleep", lambda seconds: None)
    monkeypatch.setattr("xhs_cli.qr_login.save_cookies", lambda cookies: saved.append(cookies))

    cookies = qrcode_login(timeout_s=1)
    client = _SelfInfoFallbackQrClient.instances[-1]

    assert client.activate_calls == 1
    assert client.complete_calls == 1
    assert client.self_info_calls >= 1
    assert cookies == {
        "a1": "real-a1",
        "webId": "real-webid",
        "id_token": "real-id-token",
        "web_session": "real-session",
        "web_session_sec": "real-sec",
    }
    assert saved == [cookies]


def test_qrcode_login_rejects_mismatched_confirmed_user(monkeypatch):
    monkeypatch.setattr("xhs_cli.qr_login.XhsClient", _MismatchQrClient)
    monkeypatch.setattr("xhs_cli.qr_login._generate_a1", lambda: "a1-fixed")
    monkeypatch.setattr("xhs_cli.qr_login._generate_webid", lambda: "webid-fixed")
    monkeypatch.setattr("xhs_cli.qr_login._display_qr_in_terminal", lambda data: True)
    monkeypatch.setattr("xhs_cli.qr_login.time.sleep", lambda seconds: None)
    monkeypatch.setattr("xhs_cli.qr_login.save_cookies", lambda cookies: None)

    with pytest.raises(XhsApiError, match="completion never returned"):
        qrcode_login(timeout_s=1)


def test_qrcode_login_prefers_browser_assisted_backend(monkeypatch):
    saved = []

    monkeypatch.setattr(
        "xhs_cli.qr_login._browser_assisted_qrcode_login",
        lambda **kwargs: {
            "a1": "a1-browser",
            "webId": "webid-browser",
            "web_session": "0400-browser",
            "web_session_sec": "secure-browser",
            "id_token": "token-browser",
        },
    )

    cookies = qrcode_login(timeout_s=1, prefer_browser_assisted=True)

    assert cookies["web_session"] == "0400-browser"
    assert cookies["id_token"] == "token-browser"
    assert saved == []


def test_qrcode_login_falls_back_when_browser_backend_unavailable(monkeypatch):
    monkeypatch.setattr(
        "xhs_cli.qr_login._browser_assisted_qrcode_login",
        lambda **kwargs: (_ for _ in ()).throw(BrowserQrLoginUnavailable("missing camoufox")),
    )
    monkeypatch.setattr(
        "xhs_cli.qr_login._http_qrcode_login",
        lambda **kwargs: {
            "a1": "a1-http",
            "webId": "webid-http",
            "web_session": "http-session",
        },
    )

    cookies = qrcode_login(timeout_s=1, prefer_browser_assisted=True)

    assert cookies == {
        "a1": "a1-http",
        "webId": "webid-http",
        "web_session": "http-session",
    }


def test_browser_assisted_qrcode_login_waits_for_confirmed_completion(monkeypatch):
    saved = []

    class _FakeRequest:
        def __init__(self, method):
            self.method = method

    class _FakeResponse:
        def __init__(self, url, payload, *, status=200, method="GET"):
            self.url = url
            self._payload = payload
            self.status = status
            self.request = _FakeRequest(method)
            self.headers = {}

        def json(self):
            return {"success": True, "data": self._payload}

        def text(self):
            return ""

    class _FakePage:
        def __init__(self):
            self._response_handler = None
            self._status_responses = [
                _FakeResponse(
                    "https://edith.xiaohongshu.com/api/sns/web/v1/login/qrcode/status?step=1",
                    {"codeStatus": 0},
                ),
                _FakeResponse(
                    "https://edith.xiaohongshu.com/api/sns/web/v1/login/qrcode/status?step=2",
                    {
                        "codeStatus": 2,
                        "login_info": {
                            "user_id": "real-user",
                            "session": "real-session",
                            "secure_session": "real-sec",
                        },
                    },
                ),
            ]

        def on(self, event, handler):
            assert event == "response"
            self._response_handler = handler

        def goto(self, url, wait_until=None):
            return None

        def wait_for_response(self, predicate, timeout):
            for idx, response in enumerate(list(self._status_responses)):
                if predicate(response):
                    self._status_responses.pop(idx)
                    if self._response_handler:
                        self._response_handler(response)
                    return response
            raise AssertionError("wait_for_response called without a matching fake response")

        def wait_for_url(self, pattern, timeout):
            return None

        @property
        def context(self):
            class _Ctx:
                @staticmethod
                def cookies():
                    return [
                        {"name": "a1", "value": "a1-browser", "domain": ".xiaohongshu.com"},
                        {"name": "webId", "value": "webid-browser", "domain": ".xiaohongshu.com"},
                        {"name": "web_session", "value": "real-session", "domain": ".xiaohongshu.com"},
                        {"name": "web_session_sec", "value": "real-sec", "domain": ".xiaohongshu.com"},
                    ]

            return _Ctx()

    class _FakeBrowser:
        def new_page(self):
            return _FakePage()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr("xhs_cli.qr_login._ensure_camoufox_ready", lambda: None)
    fake_camoufox = types.ModuleType("camoufox")
    fake_sync_api = types.ModuleType("camoufox.sync_api")
    fake_sync_api.Camoufox = lambda headless=False: _FakeBrowser()
    fake_camoufox.sync_api = fake_sync_api
    monkeypatch.setitem(sys.modules, "camoufox", fake_camoufox)
    monkeypatch.setitem(sys.modules, "camoufox.sync_api", fake_sync_api)
    monkeypatch.setattr("xhs_cli.qr_login._display_qr_in_terminal", lambda data: True)
    monkeypatch.setattr("xhs_cli.qr_login._wait_for_browser_login_settled", lambda page: None)
    monkeypatch.setattr("xhs_cli.qr_login.save_cookies", lambda cookies: saved.append(cookies))

    class _ExpectResponse:
        def __init__(self, response):
            self.value = response

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    qr_create_response = _FakeResponse(
        "https://edith.xiaohongshu.com/api/sns/web/v1/login/qrcode/create",
        {"url": "https://example.com/qr"},
        status=200,
        method="POST",
    )

    def _fake_expect_response(self, predicate, timeout):
        assert predicate(qr_create_response)
        return _ExpectResponse(qr_create_response)

    monkeypatch.setattr(_FakePage, "expect_response", _fake_expect_response, raising=False)

    cookies = qrcode_login(timeout_s=1, prefer_browser_assisted=True)

    assert cookies == {
        "a1": "a1-browser",
        "webId": "webid-browser",
        "web_session": "real-session",
        "web_session_sec": "real-sec",
    }
    assert saved == [cookies]


def test_normalize_browser_cookies_uses_allowlist():
    cookies = _normalize_browser_cookies([
        {"name": "a1", "value": "a1-value", "domain": ".xiaohongshu.com"},
        {"name": "web_session", "value": "session-value", "domain": ".xiaohongshu.com"},
        {"name": "customer-sso-sid", "value": "skip-me", "domain": ".xiaohongshu.com"},
        {"name": "creator_only", "value": "skip-me-too", "domain": "creator.xiaohongshu.com"},
    ])

    assert cookies == {
        "a1": "a1-value",
        "web_session": "session-value",
    }


def test_normalize_xhs_user_payload_reads_basic_info():
    user = normalize_xhs_user_payload({
        "guest": False,
        "basic_info": {
            "user_id": "user-1",
            "nickname": "Alice",
            "red_id": "alice001",
            "ip_location": "上海",
            "desc": "hello",
        },
    })

    assert user == {
        "id": "user-1",
        "name": "Alice",
        "username": "alice001",
        "nickname": "Alice",
        "red_id": "alice001",
        "ip_location": "上海",
        "desc": "hello",
        "guest": False,
    }
