"""QR code login for Xiaohongshu.

Supports two backends:
1. Browser-assisted login via Camoufox.  The browser performs the real
   QR completion flow, while the CLI renders the QR code in the terminal
   from the browser's ``qrcode/create`` response and exports cookies after
   login succeeds.
2. Legacy pure-HTTP login flow.  This remains as a fallback when the
   browser backend is unavailable.
"""

from __future__ import annotations

import logging
import random
import subprocess
import sys
import time
from typing import Any

from .client import XhsClient
from .cookies import save_cookies
from .exceptions import NeedVerifyError, XhsApiError

logger = logging.getLogger(__name__)

LOGIN_URL = "https://www.xiaohongshu.com/login"
QR_CREATE_ENDPOINT = "/api/sns/web/v1/login/qrcode/create"
QR_USERINFO_ENDPOINT = "/api/qrcode/userinfo"
QR_STATUS_ENDPOINT = "/api/sns/web/v1/login/qrcode/status"

# QR code status values
QR_WAITING = 0      # Waiting for scan
QR_SCANNED = 1      # Scanned, awaiting confirmation
QR_CONFIRMED = 2    # Login confirmed

# Poll config
POLL_INTERVAL_S = 2.0
POLL_TIMEOUT_S = 240  # 4 minutes
BROWSER_EXPORT_COOKIE_NAMES = (
    "a1",
    "webId",
    "web_session",
    "web_session_sec",
    "id_token",
    "websectiga",
    "sec_poison_id",
    "xsecappid",
    "gid",
    "abRequestId",
    "webBuild",
    "loadts",
)
PERSISTED_COOKIE_NAMES = BROWSER_EXPORT_COOKIE_NAMES


class BrowserQrLoginUnavailable(XhsApiError):
    """Raised when the browser-assisted QR backend cannot be started."""


def _emit_status(on_status: callable[[str], None] | None, msg: str) -> None:
    """Send a status message to the callback or stdout."""
    if on_status:
        on_status(msg)
    else:
        print(msg)


def _apply_session_cookies(client: XhsClient, payload: dict[str, Any]) -> None:
    """Persist any session cookies returned by the QR login endpoints."""
    login_info = payload.get("login_info", {})
    if not isinstance(login_info, dict):
        login_info = {}
    session = payload.get("session") or login_info.get("session", "")
    secure_session = payload.get("secure_session") or login_info.get("secure_session", "")
    if session:
        client.cookies["web_session"] = str(session)
    if secure_session:
        client.cookies["web_session_sec"] = str(secure_session)


def _build_saved_cookies(
    fallback_a1: str,
    fallback_webid: str,
    payload: dict[str, Any],
) -> dict[str, str]:
    """Build the cookie payload persisted after QR login succeeds."""
    login_info = payload.get("login_info", {})
    if not isinstance(login_info, dict):
        login_info = {}
    session = payload.get("session") or login_info.get("session") or payload.get("web_session", "")
    secure_session = (
        payload.get("secure_session")
        or login_info.get("secure_session")
        or payload.get("web_session_sec", "")
    )
    cookies = {}
    a1 = payload.get("a1") or fallback_a1
    webid = payload.get("webId") or payload.get("webid") or fallback_webid
    if a1:
        cookies["a1"] = str(a1)
    if webid:
        cookies["webId"] = str(webid)
    if session:
        cookies["web_session"] = str(session)
    if secure_session:
        cookies["web_session_sec"] = str(secure_session)
    for name in PERSISTED_COOKIE_NAMES:
        value = payload.get(name)
        if value:
            cookies[name] = str(value)
    return cookies


def _persistable_cookie_subset(cookies: dict[str, Any]) -> dict[str, str]:
    """Filter an in-memory cookie jar down to the persisted local cookie shape."""
    persisted: dict[str, str] = {}
    for name in PERSISTED_COOKIE_NAMES:
        value = cookies.get(name)
        if value:
            persisted[name] = str(value)
    return persisted


def _normalize_browser_cookies(raw_cookies: list[dict[str, Any]]) -> dict[str, str]:
    """Convert Playwright cookies into the local persisted cookie shape."""
    cookies: dict[str, str] = {}
    for entry in raw_cookies:
        name = entry.get("name")
        value = entry.get("value")
        domain = entry.get("domain", "")
        if not isinstance(name, str) or not isinstance(value, str):
            continue
        if name not in BROWSER_EXPORT_COOKIE_NAMES:
            continue
        if not isinstance(domain, str) or "xiaohongshu.com" not in domain:
            continue
        cookies[name] = value
    return cookies


def _unwrap_browser_response_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the inner `data` payload when browser responses use the common envelope."""
    data = payload.get("data")
    if isinstance(data, dict):
        return data
    return payload


def _browser_response_payload(response: Any) -> dict[str, Any]:
    """Decode a browser response body as JSON and unwrap the common envelope."""
    try:
        data = response.json()
    except Exception as exc:
        raise XhsApiError(f"Browser response from {response.url} was not valid JSON.") from exc
    if not isinstance(data, dict):
        raise XhsApiError(f"Browser response from {response.url} returned unexpected payload: {data!r}")
    return _unwrap_browser_response_payload(data)


def _raise_for_browser_response(response: Any) -> None:
    """Map browser QR completion failures onto the same domain errors as the HTTP client."""
    status = getattr(response, "status", None)
    if status in (461, 471):
        raise NeedVerifyError(
            verify_type=response.headers.get("verifytype", "unknown"),
            verify_uuid=response.headers.get("verifyuuid", "unknown"),
        )
    if status and status >= 400:
        try:
            body = response.text()
        except Exception:
            body = "<unavailable>"
        raise XhsApiError(
            f"Browser-assisted QR completion failed: HTTP {status} body={body[:300]}"
        )


def _qr_code_status(payload: dict[str, Any]) -> int:
    """Read a QR status payload regardless of snake/camel case naming."""
    raw_status = payload.get("code_status", payload.get("codeStatus", -1))
    try:
        return int(raw_status)
    except (TypeError, ValueError):
        return -1


def _browser_completion_ready(payload: dict[str, Any]) -> bool:
    """Return True once the browser completion payload represents a real login."""
    if _qr_code_status(payload) == QR_CONFIRMED:
        return True

    login_info = payload.get("login_info")
    if isinstance(login_info, dict) and (
        login_info.get("session")
        or login_info.get("secure_session")
        or login_info.get("user_id")
        or login_info.get("userId")
    ):
        return True

    return bool(
        payload.get("session")
        or payload.get("secure_session")
        or payload.get("user_id")
        or payload.get("userId")
    )


def _wait_for_confirmed_browser_completion(page: Any, *, timeout_s: int) -> dict[str, Any]:
    """Wait until the browser QR completion endpoint reports a confirmed login."""
    deadline = time.time() + timeout_s
    last_payload: dict[str, Any] = {}

    while True:
        remaining_ms = max(1, int((deadline - time.time()) * 1000))
        if remaining_ms <= 1 and time.time() >= deadline:
            break

        try:
            response = page.wait_for_response(
                lambda resp: QR_STATUS_ENDPOINT in resp.url and resp.request.method == "GET",
                timeout=remaining_ms,
            )
        except Exception as exc:
            raise XhsApiError(
                "QR code login timed out while waiting for browser confirmation."
            ) from exc

        _raise_for_browser_response(response)
        payload = _browser_response_payload(response)
        last_payload = payload

        logger.debug(
            "Browser QR completion poll: codeStatus=%s payload=%s",
            _qr_code_status(payload),
            payload,
        )
        if _browser_completion_ready(payload):
            return payload

    raise XhsApiError(
        "QR code login timed out before browser completion returned a confirmed session. "
        f"last_status={_qr_code_status(last_payload)} payload={last_payload}"
    )


def _wait_for_browser_login_settled(page: Any) -> None:
    """Wait briefly for the browser session and post-login page state to stabilize."""
    try:
        page.wait_for_url("**/explore*", timeout=5_000)
    except Exception:
        logger.debug("Browser-assisted QR login did not navigate to /explore before timeout")

    try:
        response = page.wait_for_response(
            lambda resp: "/api/sns/web/v2/user/me" in resp.url and resp.request.method == "GET",
            timeout=5_000,
        )
    except Exception:
        logger.debug("Browser-assisted QR login did not observe a post-login user/me response before timeout")
        return

    try:
        payload = _browser_response_payload(response)
    except Exception as exc:
        logger.debug("Failed to parse browser user/me response after QR login: %s", exc)
        return

    if bool(payload.get("guest", False)):
        logger.debug("Browser-assisted QR login settled with guest=true in user/me payload: %s", payload)


def _export_browser_context_cookies(page: Any) -> dict[str, str]:
    """Export cookies directly from the live browser context."""
    return _normalize_browser_cookies(page.context.cookies())


def _validate_browser_exported_session(
    cookies: dict[str, str],
    *,
    retries: int = 3,
    wait_s: float = 1.5,
) -> tuple[dict[str, str], str]:
    """Validate cookies exported from Camoufox and merge response cookies."""
    if not cookies:
        raise XhsApiError("Browser-assisted QR login did not export any cookies.")

    last_error: Exception | None = None
    last_user_id = ""

    for attempt in range(retries):
        try:
            with XhsClient(dict(cookies), request_delay=0) as client:
                info = client.get_self_info()
                merged = dict(client.cookies)
        except NeedVerifyError:
            return dict(cookies), ""
        except Exception as exc:
            last_error = exc
        else:
            last_user_id = _resolved_user_id(info)
            if not bool(info.get("guest", False)):
                return merged, last_user_id
            last_error = XhsApiError(f"guest session after browser-assisted login: {info}")

        if attempt + 1 < retries:
            time.sleep(wait_s)

    raise XhsApiError(
        "Browser-assisted QR login exported cookies, but they did not validate "
        f"as a logged-in session. user_id={last_user_id or 'unknown'} error={last_error}"
    )


def _resolved_user_id(info: dict[str, object]) -> str:
    """Extract the current user ID from activate/self payloads."""
    if not isinstance(info, dict):
        return ""
    login_info = info.get("login_info")
    if isinstance(login_info, dict):
        if login_info.get("user_id"):
            return str(login_info["user_id"])
        if login_info.get("userId"):
            return str(login_info["userId"])
    basic = info.get("basic_info", info)
    if isinstance(basic, dict) and basic.get("user_id"):
        return str(basic["user_id"])
    if info.get("user_id"):
        return str(info["user_id"])
    if info.get("userId"):
        return str(info["userId"])
    if info.get("userid"):
        return str(info["userid"])
    return ""


def _complete_confirmed_session(
    client: XhsClient,
    qr_id: str,
    code: str,
    confirmed_user_id: str,
    *,
    retries: int = 5,
    wait_s: float = 1.0,
) -> dict[str, object]:
    """Finalize QR login after confirmation until the session switches users."""
    last_data: dict[str, object] = {}
    last_self_info_user_id = ""
    initial_session = str(client.cookies.get("web_session", "") or "")
    initial_secure_session = str(client.cookies.get("web_session_sec", "") or "")
    for attempt in range(retries):
        completion_data = client.complete_qr_login(qr_id, code)
        _apply_session_cookies(client, completion_data)
        last_data = completion_data
        completed_user_id = _resolved_user_id(completion_data)
        self_info_user_id = ""
        try:
            self_info_user_id = _resolved_user_id(client.get_self_info())
            last_self_info_user_id = self_info_user_id
        except Exception as exc:
            logger.debug(
                "QR post-confirm self info check failed attempt=%d: %s",
                attempt + 1,
                exc,
            )
        logger.debug(
            "QR post-confirm completion attempt=%d confirmed_user_id=%s "
            "completion_user_id=%s self_info_user_id=%s session_changed=%s cookies=%s data=%s",
            attempt + 1,
            confirmed_user_id,
            completed_user_id,
            self_info_user_id,
            (
                client.cookies.get("web_session") != initial_session
                or client.cookies.get("web_session_sec") != initial_secure_session
            ),
            {
                "a1": client.cookies.get("a1"),
                "webId": client.cookies.get("webId"),
                "web_session": client.cookies.get("web_session"),
                "web_session_sec": client.cookies.get("web_session_sec"),
                "id_token": client.cookies.get("id_token"),
            },
            completion_data,
        )
        session_changed = (
            str(client.cookies.get("web_session", "") or "") != initial_session
            or str(client.cookies.get("web_session_sec", "") or "") != initial_secure_session
        )
        if session_changed and completed_user_id and completed_user_id == confirmed_user_id:
            return completion_data
        if session_changed and self_info_user_id and self_info_user_id == confirmed_user_id:
            return completion_data
        if attempt + 1 < retries:
            time.sleep(wait_s)

    raise XhsApiError(
        "QR login confirmed, but completion never returned the confirmed user session. "
        f"expected={confirmed_user_id} "
        f"completion_user={_resolved_user_id(last_data) or 'unknown'} "
        f"self_info_user={last_self_info_user_id or 'unknown'} "
        f"completion_data={last_data}"
    )


def _generate_a1() -> str:
    """Generate a fresh a1 cookie value (52 hex chars with embedded timestamp)."""
    prefix = "".join(random.choices("0123456789abcdef", k=24))
    ts = str(int(time.time() * 1000))
    suffix = "".join(random.choices("0123456789abcdef", k=15))
    return prefix + ts + suffix


def _generate_webid() -> str:
    """Generate a webId cookie value (32 hex chars)."""
    return "".join(random.choices("0123456789abcdef", k=32))


def _render_qr_half_blocks(matrix: list[list[bool]]) -> str:
    """Render QR matrix using half-block characters (▀▄█ and space)."""
    if not matrix:
        return ""

    size = len(matrix)
    lines: list[str] = []

    for row_idx in range(0, size, 2):
        line = ""
        for col_idx in range(size):
            top = matrix[row_idx][col_idx]
            bot = matrix[row_idx + 1][col_idx] if row_idx + 1 < size else False

            if top and bot:
                line += "█"
            elif top and not bot:
                line += "▀"
            elif not top and bot:
                line += "▄"
            else:
                line += " "

        lines.append(line)

    return "\n".join(lines)


def _display_qr_in_terminal(data: str) -> bool:
    """Display *data* as a QR code in the terminal.  Returns True on success."""
    try:
        import qrcode  # type: ignore[import-untyped]
    except ImportError:
        return False

    qr = qrcode.QRCode(border=4)
    qr.add_data(data)
    qr.make(fit=True)

    modules = qr.get_matrix()
    print(_render_qr_half_blocks(modules))
    return True


def _ensure_camoufox_ready() -> None:
    """Validate that the Camoufox package and browser binary are available."""
    try:
        import camoufox  # noqa: F401
    except ImportError as exc:
        raise BrowserQrLoginUnavailable(
            "Browser-assisted QR login requires the `camoufox` package."
        ) from exc

    try:
        result = subprocess.run(
            [sys.executable, "-m", "camoufox", "path"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BrowserQrLoginUnavailable(
            "Unable to validate the Camoufox browser installation."
        ) from exc

    if result.returncode != 0 or not result.stdout.strip():
        raise BrowserQrLoginUnavailable(
            "Camoufox browser runtime is missing. Run `python -m camoufox fetch` first."
        )


def _browser_assisted_qrcode_login(
    *,
    on_status: callable[[str], None] | None = None,
    timeout_s: int = POLL_TIMEOUT_S,
) -> dict[str, str]:
    """Log in by letting a real browser complete the QR flow, then export cookies."""
    _ensure_camoufox_ready()

    try:
        from camoufox.sync_api import Camoufox
    except ImportError as exc:
        raise BrowserQrLoginUnavailable(
            "Camoufox sync API is unavailable in the current environment."
        ) from exc

    state: dict[str, Any] = {"last_status": -1, "completion_data": {}}

    _emit_status(on_status, "🔑 Starting browser-assisted QR login...")

    with Camoufox(headless=False) as browser:
        page = browser.new_page()

        def _handle_response(response) -> None:
            url = response.url
            if (
                QR_USERINFO_ENDPOINT not in url
                and QR_STATUS_ENDPOINT not in url
                and "/api/sns/web/v2/user/me" not in url
            ):
                return
            try:
                payload = _unwrap_browser_response_payload(response.json())
            except Exception as exc:
                logger.debug("Failed to parse browser QR poll response: %s", exc)
                return

            if QR_STATUS_ENDPOINT in url and isinstance(payload, dict):
                state["completion_data"] = payload

            code_status = int(payload.get("codeStatus", -1))
            if code_status == state["last_status"]:
                return
            state["last_status"] = code_status

            if code_status == QR_SCANNED:
                _emit_status(on_status, "📲 Scanned! Waiting for confirmation...")
            elif code_status == QR_CONFIRMED:
                _emit_status(on_status, "✅ Login confirmed!")

        page.on("response", _handle_response)

        try:
            with page.expect_response(
                lambda response: QR_CREATE_ENDPOINT in response.url and response.request.method == "POST",
                timeout=20_000,
            ) as qr_response_info:
                page.goto(LOGIN_URL, wait_until="domcontentloaded")
        except Exception as exc:
            raise XhsApiError("Failed to load Xiaohongshu login page in Camoufox.") from exc

        qr_payload = _browser_response_payload(qr_response_info.value)
        qr_url = str(qr_payload.get("url", "")).strip()
        if not qr_url:
            raise XhsApiError(f"Browser-assisted QR login did not expose a QR URL: {qr_payload}")

        _emit_status(on_status, "\n📱 Scan the QR code below with the Xiaohongshu app:\n")
        if not _display_qr_in_terminal(qr_url):
            _emit_status(on_status, "⚠️  Install 'qrcode' for terminal rendering: pip install qrcode")
            _emit_status(on_status, f"QR URL: {qr_url}")
        _emit_status(on_status, "\n⏳ Waiting for QR code scan...")

        deadline = time.time() + timeout_s
        last_validation_error: Exception | None = None
        settled_after_confirm = False

        while time.time() < deadline:
            if page.is_closed():
                raise XhsApiError("Browser-assisted QR login browser window was closed before login completed.")

            if state["last_status"] == QR_CONFIRMED and not settled_after_confirm:
                _wait_for_browser_login_settled(page)
                settled_after_confirm = True

            completion_data = state.get("completion_data", {})
            if not isinstance(completion_data, dict):
                completion_data = {}
            login_info = completion_data.get("login_info", {})
            if not isinstance(login_info, dict):
                login_info = {}

            cookies = _export_browser_context_cookies(page)
            session = login_info.get("session")
            secure_session = login_info.get("secure_session")
            if isinstance(session, str) and session:
                cookies["web_session"] = session
            if isinstance(secure_session, str) and secure_session:
                cookies["web_session_sec"] = secure_session

            if cookies.get("a1") and cookies.get("webId"):
                try:
                    validated_cookies, user_id = _validate_browser_exported_session(
                        cookies,
                        retries=1,
                        wait_s=0,
                    )
                except Exception as exc:
                    last_validation_error = exc
                    logger.debug("Browser cookie validation not ready yet: %s", exc)
                else:
                    save_cookies(validated_cookies)
                    if user_id:
                        _emit_status(on_status, f"👤 User ID: {user_id}")
                    else:
                        _emit_status(on_status, "Browser cookies exported and saved.")
                    return validated_cookies

            time.sleep(0.8 if state["last_status"] == QR_CONFIRMED else 1.5)

        raise XhsApiError(
            "Browser-assisted QR login timed out before exported browser cookies became a valid session. "
            f"last_status={state.get('last_status', -1)} "
            f"completion_data={state.get('completion_data', {})} "
            f"last_validation_error={last_validation_error}"
        )


def _http_qrcode_login(
    *,
    on_status: callable[[str], None] | None = None,
    timeout_s: int = POLL_TIMEOUT_S,
) -> dict[str, str]:
    """Run the legacy pure-HTTP QR login flow."""
    a1 = _generate_a1()
    webid = _generate_webid()
    tmp_cookies = {"a1": a1, "webId": webid}

    _emit_status(on_status, "🔑 Starting QR code login...")

    with XhsClient(tmp_cookies, request_delay=0) as client:
        try:
            activate_data = client.login_activate()
            _apply_session_cookies(client, activate_data)
            guest_session = activate_data.get("session", "")
            logger.debug(
                "Initial activate: session=%s user_id=%s",
                guest_session, activate_data.get("user_id"),
            )
        except Exception as exc:
            logger.debug("Initial activate failed (non-fatal): %s", exc)

        qr_data = client.create_qr_login()
        qr_id = qr_data["qr_id"]
        code = qr_data["code"]
        qr_url = qr_data["url"]

        logger.debug("QR created: qr_id=%s, code=%s", qr_id, code)

        _emit_status(on_status, "\n📱 Scan the QR code below with the Xiaohongshu app:\n")
        if not _display_qr_in_terminal(qr_url):
            _emit_status(on_status, "⚠️  Install 'qrcode' for terminal rendering: pip install qrcode")
            _emit_status(on_status, f"QR URL: {qr_url}")
        _emit_status(on_status, "\n⏳ Waiting for QR code scan...")

        start = time.time()
        last_status = -1
        consecutive_errors = 0

        while (time.time() - start) < timeout_s:
            time.sleep(POLL_INTERVAL_S)

            try:
                status_data = client.check_qr_status(qr_id, code)
            except Exception as exc:
                logger.debug("QR status check error: %s", exc)
                consecutive_errors += 1
                if consecutive_errors >= 3:
                    raise XhsApiError(f"QR status polling failed repeatedly: {exc}") from exc
                continue
            else:
                consecutive_errors = 0

            code_status = status_data.get("codeStatus", -1)
            logger.debug("QR poll: codeStatus=%s data=%s", code_status, status_data)

            if code_status != last_status:
                last_status = code_status
                if code_status == QR_SCANNED:
                    _emit_status(on_status, "📲 Scanned! Waiting for confirmation...")
                elif code_status == QR_CONFIRMED:
                    _emit_status(on_status, "✅ Login confirmed!")

            if code_status == QR_CONFIRMED:
                confirmed_user_id = status_data.get("userId", "")
                if not confirmed_user_id:
                    raise XhsApiError("QR login confirmed but no confirmed userId was returned.")

                completion_data = _complete_confirmed_session(
                    client,
                    qr_id,
                    code,
                    confirmed_user_id,
                )
                user_id = _resolved_user_id(completion_data) or confirmed_user_id
                cookies = _persistable_cookie_subset(client.cookies)
                cookies = {
                    **_build_saved_cookies(a1, webid, completion_data),
                    **cookies,
                }
                save_cookies(cookies)
                _emit_status(on_status, f"👤 User ID: {user_id}")
                return cookies

            elapsed = time.time() - start
            if int(elapsed) % 30 == 0 and int(elapsed) > 0:
                _emit_status(on_status, "  Still waiting...")

    raise XhsApiError("QR code login timed out after 4 minutes")


def qrcode_login(
    *,
    on_status: callable[[str], None] | None = None,
    timeout_s: int = POLL_TIMEOUT_S,
    prefer_browser_assisted: bool = False,
) -> dict[str, str]:
    """Run the QR code login flow."""
    if prefer_browser_assisted:
        try:
            return _browser_assisted_qrcode_login(on_status=on_status, timeout_s=timeout_s)
        except BrowserQrLoginUnavailable as exc:
            logger.info("Browser-assisted QR login unavailable, falling back to HTTP flow: %s", exc)

    return _http_qrcode_login(on_status=on_status, timeout_s=timeout_s)
