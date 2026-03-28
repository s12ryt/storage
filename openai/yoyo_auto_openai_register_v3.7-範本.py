"""
OpenAI 自動化工具 - 整合版 v3.7
================================
支援功能:
1. 自動註冊新帳號（永不停歇模式）
2. 批量登入現有帳號
3. 智能降級機制：
   - 註冊成功 → 保存 token → 繼續下一個（不執行降級）
   - 註冊失敗 → 執行降級登入 → 繼續下一個（不論降級結果）
   - 無論成功或失敗，都永遠繼續下一輪註冊

核心邏輯:
    while True:
        token = run_register()
        if token:
            保存 token           # 成功，不降級
        else:
            降級登入()           # 失敗，執行降級
        繼續下一個新的註冊  ← 永遠循環

自動降級觸發條件:
- 無法獲取授權 Cookie
- 授權 Cookie 里沒有 workspace 信息
- 無法解析 workspace_id
- workspace 選擇失敗
- Callback URL 捕獲失敗
- OTP 獲取超時
- 其他註冊流程異常

用法:
    python yoyo_auto_openai_unified.py --mode register --proxy http://127.0.0.1:7890
    python yoyo_auto_openai_unified.py --mode login --accounts qzz-accounts.txt --proxy http://127.0.0.1:7890
    python yoyo_auto_openai_unified.py --mode auto --accounts qzz-accounts.txt --proxy http://127.0.0.1:7890
"""

import json
import os
import re
import sys
import time
import math
import random
import string
import secrets
import hashlib
import base64
import argparse
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs, urlencode, quote, urljoin
from dataclasses import dataclass
from typing import Any, Dict, Optional, List, Tuple
from enum import Enum

from curl_cffi import requests


# ==========================================
# 配置區塊
# ==========================================

class AuthMode(Enum):
    """認證模式枚舉"""
    LOGIN = "login"           # 純登入模式
    REGISTER = "register"     # 純註冊模式
    AUTO = "auto"            # 自動模式：先註冊，失敗則登入

# Worker API 配置（用於郵箱和 OTP）
WORKER_DOMAIN = ""
WORKER_API_KEY = ""
OTP_WAIT_SECONDS = 75

# OAuth 配置
AUTH_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
REDIRECT_URI = "http://localhost:1455/auth/callback"
SCOPE = "openid email profile offline_access"

# 結果輸出目錄
TOKEN_OUTPUT_DIR = os.getenv("TOKEN_OUTPUT_DIR", "").strip()
ACCOUNTS_FILE = "accounts.txt"


# ==========================================
# 工具函數
# ==========================================

def _ssl_verify() -> bool:
    """檢查是否啟用 SSL 驗證"""
    flag = os.getenv("OPENAI_SSL_VERIFY", "1").strip().lower()
    return flag not in {"0", "false", "no", "off"}


def _response_preview(text: str, limit: int = 240) -> str:
    """壓縮回應文字用於日誌"""
    compact = " ".join((text or "").split())
    if len(compact) <= limit:
        return compact
    return compact[:limit] + "..."


def _now_local() -> datetime:
    return datetime.now().astimezone()


def _iso_local(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _append_line(path: str, line: str) -> None:
    """追加一行到檔案"""
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(line.rstrip("\n") + "\n")


def _result_file_paths(base_dir: str, run_ts: str) -> Dict[str, str]:
    """生成結果檔案路徑"""
    return {
        "success": os.path.join(base_dir, f"result_success_{run_ts}.txt"),
        "wrong_code": os.path.join(base_dir, f"result_wrong_code_{run_ts}.txt"),
        "deactivated": os.path.join(base_dir, f"result_deactivated_{run_ts}.txt"),
        "other_fail": os.path.join(base_dir, f"result_other_fail_{run_ts}.txt"),
        "auto_fallback": os.path.join(base_dir, f"result_auto_fallback_{run_ts}.txt"),
    }


def _categorize_failure(reason: str) -> str:
    """分類失敗原因"""
    text = (reason or "").lower()
    if "wrong code" in text or "incorrect code" in text:
        return "wrong_code"
    if "deleted or deactivated" in text or "deactivated" in text:
        return "deactivated"
    return "other_fail"


def _b64url_no_pad(raw: bytes) -> str:
    """Base64 URL-safe 編碼（無填充）"""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _sha256_b64url_no_pad(s: str) -> str:
    """字串 SHA256 後 Base64 URL-safe 編碼"""
    return _b64url_no_pad(hashlib.sha256(s.encode("ascii")).digest())


def _random_state(nbytes: int = 16) -> str:
    """生成隨機 state"""
    return secrets.token_urlsafe(nbytes)


def _pkce_verifier() -> str:
    """生成 PKCE code_verifier"""
    return secrets.token_urlsafe(64)


def _decode_jwt_segment(seg: str) -> Dict[str, Any]:
    """解碼 JWT 段（不解驗證簽名）"""
    raw = (seg or "").strip()
    if not raw:
        return {}
    pad = "=" * ((4 - (len(raw) % 4)) % 4)
    try:
        decoded = base64.urlsafe_b64decode((raw + pad).encode("ascii"))
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}


def _to_int(v: Any) -> int:
    """安全轉整數"""
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _parse_callback_url(callback_url: str) -> Dict[str, Any]:
    """解析 OAuth callback URL"""
    candidate = callback_url.strip()
    if not candidate:
        return {"code": "", "state": "", "error": "", "error_description": ""}

    if "://" not in candidate:
        if candidate.startswith("?"):
            candidate = f"http://localhost{candidate}"
        elif any(ch in candidate for ch in "/?#") or ":" in candidate:
            candidate = f"http://{candidate}"
        elif "=" in candidate:
            candidate = f"http://localhost/?{candidate}"

    parsed = urlparse(candidate)
    query = parse_qs(parsed.query, keep_blank_values=True)
    fragment = parse_qs(parsed.fragment, keep_blank_values=True)

    for key, values in fragment.items():
        if key not in query or not query[key] or not (query[key][0] or "").strip():
            query[key] = values

    def get1(k: str) -> str:
        v = query.get(k, [""])
        return (v[0] or "").strip()

    code = get1("code")
    state = get1("state")
    error = get1("error")
    error_description = get1("error_description")

    if code and not state and "#" in code:
        code, state = code.split("#", 1)

    if not error and error_description:
        error, error_description = error_description, ""

    return {
        "code": code,
        "state": state,
        "error": error,
        "error_description": error_description,
    }


def _extract_next_url(data: Dict[str, Any]) -> str:
    """從回應中提取下一跳 URL"""
    continue_url = str(data.get("continue_url") or "").strip()
    if continue_url:
        return continue_url
    page_type = str((data.get("page") or {}).get("type") or "").strip()
    
    mapping = {
        "email_otp_verification": "https://auth.openai.com/email-verification",
        "sign_in_with_chatgpt_codex_consent": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
        "sign_in_with_chatgpt_codex_org": "https://auth.openai.com/sign-in-with-chatgpt/codex/organization",
        "workspace": "https://auth.openai.com/workspace",
    }
    return mapping.get(page_type, "")


def _follow_redirect_chain(
    session: requests.Session,
    start_url: str,
    proxies: Optional[Dict[str, str]],
    *,
    max_redirects: int = 12,
) -> Tuple[Optional[requests.Response], str]:
    """跟隨重定向鏈"""
    current_url = start_url
    response = None

    for _ in range(max_redirects):
        response = session.get(
            current_url,
            allow_redirects=False,
            proxies=proxies,
            verify=_ssl_verify(),
            timeout=15,
        )
        if response.status_code not in [301, 302, 303, 307, 308]:
            return response, current_url

        location = response.headers.get("Location", "")
        if not location:
            return response, current_url

        current_url = urljoin(current_url, location)
        if "code=" in current_url and "state=" in current_url:
            return None, current_url

    return response, current_url


def _extract_json_error(resp: Any) -> str:
    """從回應中提取 JSON 錯誤訊息"""
    try:
        data = resp.json()
    except Exception:
        return ""

    if isinstance(data, dict):
        error = data.get("error")
        if isinstance(error, dict):
            return str(error.get("message") or error.get("code") or "").strip()
        return str(data.get("error_description") or error or "").strip()

    return ""


# ==========================================
# OAuth 工具
# ==========================================

@dataclass(frozen=True)
class OAuthStart:
    """OAuth 起始參數"""
    auth_url: str
    state: str
    code_verifier: str
    redirect_uri: str


def generate_oauth_url(
    redirect_uri: str = REDIRECT_URI,
    scope: str = SCOPE
) -> OAuthStart:
    """生成 OAuth 授權 URL"""
    state = _random_state()
    code_verifier = _pkce_verifier()
    code_challenge = _sha256_b64url_no_pad(code_verifier)

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "prompt": "login",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    }
    auth_url = f"{AUTH_URL}?{urlencode(params)}"
    return OAuthStart(
        auth_url=auth_url,
        state=state,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
    )


def submit_callback_url(
    callback_url: str,
    expected_state: str,
    code_verifier: str,
    redirect_uri: str = REDIRECT_URI,
    account_email: str = "",
    account_password: str = "",
) -> Optional[str]:
    """提交 OAuth callback URL，換取 Token"""
    try:
        cb = _parse_callback_url(callback_url)
        if cb["error"]:
            raise RuntimeError(f"oauth error: {cb['error']}: {cb['error_description']}".strip())

        if not cb["code"]:
            raise ValueError("callback url missing ?code=")
        if not cb["state"]:
            raise ValueError("callback url missing ?state=")
        if cb["state"] != expected_state:
            raise ValueError("state mismatch")

        # 發送 token 請求
        token_resp = requests.post(
            TOKEN_URL,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            data=urlencode({
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "code": cb["code"],
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            }),
            impersonate="chrome",
            verify=_ssl_verify(),
            timeout=15,
        )

        if token_resp.status_code != 200:
            raise RuntimeError(f"token exchange failed: {token_resp.status_code}: {token_resp.text}")

        token_data = token_resp.json()
        access_token = (token_data.get("access_token") or "").strip()
        refresh_token = (token_data.get("refresh_token") or "").strip()
        id_token = (token_data.get("id_token") or "").strip()
        expires_in = _to_int(token_data.get("expires_in"))

        # 解析 JWT 獲取用戶信息
        claims = _decode_jwt_segment(id_token.split(".")[1]) if "." in id_token else {}
        email = str(claims.get("email") or "").strip()
        auth_claims = claims.get("https://api.openai.com/auth") or {}
        account_id = str(auth_claims.get("chatgpt_account_id") or "").strip()

        now = int(time.time())
        expired_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + max(expires_in, 0)))
        now_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

        config = {
            "id_token": id_token,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "account_id": account_id,
            "last_refresh": now_rfc3339,
            "email": email,
            "type": "codex",
            "expired": expired_rfc3339,
        }
        
        if account_email:
            config["account_email"] = account_email
        if account_password:
            config["account_password"] = account_password

        return json.dumps(config, ensure_ascii=False, separators=(",", ":"))
        
    except Exception as e:
        print(f"[Error] Token 兌換失敗: {e}")
        return None


# ==========================================
# Sentinel Token 工具
# ==========================================

def _build_sentinel_header(
    session: requests.Session,
    flow: str,
    proxies: Optional[Dict[str, str]],
) -> Optional[str]:
    """構建 Sentinel Token"""
    did = session.cookies.get("oai-did")
    if not did:
        return None

    try:
        sentinel_resp = requests.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            headers={
                "Origin": "https://sentinel.openai.com",
                "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6",
                "Content-Type": "text/plain;charset=UTF-8",
            },
            data=json.dumps({"p": "", "id": did, "flow": flow}),
            proxies=proxies,
            impersonate="chrome",
            verify=_ssl_verify(),
            timeout=15,
        )
        if sentinel_resp.status_code != 200:
            print(f"[Warn] Sentinel token request failed for flow {flow}: HTTP {sentinel_resp.status_code}")
            return None

        token = str((sentinel_resp.json() or {}).get("token") or "").strip()
        if not token:
            print(f"[Warn] Sentinel token missing for flow {flow}")
            return None

        return json.dumps(
            {"p": "", "t": "", "c": token, "id": did, "flow": flow},
            ensure_ascii=False,
            separators=(",", ":"),
        )
    except Exception as exc:
        print(f"[Warn] Sentinel token request error for flow {flow}: {exc}")
        return None


# ==========================================
# Worker API 工具（郵箱和 OTP）
# ==========================================

def _curl_request(url: str, method: str = "GET", proxies: Optional[Dict[str, str]] = None) -> str:
    """透過 curl 發送 HTTP 請求"""
    import subprocess
    
    cmd = ["curl", "-s", "-m", "10"]
    if proxies:
        proxy = proxies.get("http", "") or proxies.get("https", "")
        if proxy:
            cmd.extend(["-x", proxy])
    if method == "POST":
        cmd.extend(["-X", "POST"])
    cmd.append(url)
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return result.stdout.strip()
    except Exception:
        return ""


def create_worker_mailbox(proxies: Optional[Dict[str, str]] = None) -> Tuple[str, str]:
    """透過 Worker API 創建新郵箱，返回 (email, mailbox_id)"""
    url = f"{WORKER_DOMAIN}/api/remail?key={WORKER_API_KEY}"
    
    result = _curl_request(url, "POST", proxies)
    
    if not result:
        return "", ""
    
    try:
        data = json.loads(result)
        email = data.get("email", "")
        mailbox_id = data.get("id", "")
        
        if email and mailbox_id:
            print(f"[*] Worker 郵箱創建成功: {email}")
            return email, mailbox_id
        
        print(f"[!] Worker API 響應異常: {result[:200]}")
        return "", ""
    except Exception as e:
        print(f"[!] 創建郵箱失敗: {e}")
        return "", ""


def get_otp_from_worker_mailbox(mailbox_id: str, proxies: Optional[Dict[str, str]] = None) -> str:
    """透過 Worker API 輪詢 OTP"""
    import re
    
    if not mailbox_id:
        print("[!] 缺少 mailbox_id")
        return ""
    
    max_attempts = 15
    attempt = 0
    
    while attempt < max_attempts:
        attempt += 1
        
        inbox_url = f"{WORKER_DOMAIN}/api/inbox?key={WORKER_API_KEY}&mailbox_id={mailbox_id}"
        result = _curl_request(inbox_url, "GET", proxies)
        
        if not result:
            print(f"[*] Worker API 無響應，嘗試 {attempt}/{max_attempts}...")
            time.sleep(5)
            continue
        
        try:
            inbox_data = json.loads(result)
        except json.JSONDecodeError:
            print(f"[*] JSON 解析失敗，嘗試 {attempt}/{max_attempts}...")
            time.sleep(5)
            continue
        
        # Worker API 返回 list 直接是郵件陣列
        mails = inbox_data if isinstance(inbox_data, list) else inbox_data.get("mails", [])
        print(f"[*] 檢查 {attempt}/{max_attempts}, 郵件數: {len(mails)}")
        
        code = None
        
        if mails:
            latest_mail = mails[0]
            mail_id = latest_mail.get("mail_id", "") or latest_mail.get("id", "")
            
            if mail_id:
                mail_url = f"{WORKER_DOMAIN}/api/mail?key={WORKER_API_KEY}&id={mail_id}"
                mail_result = _curl_request(mail_url, "GET", proxies)
                
                if mail_result:
                    try:
                        mail_data = json.loads(mail_result)
                    except Exception:
                        mail_data = {"content": mail_result}
                    
                    content = str(mail_data.get("content", "") or mail_result)
                    
                    # 解析驗證碼 - 多種模式
                    patterns = [
                        r'font-size:24px[^>]*>[\s\n]*(\d{6})[\s\n]*<',
                        r'(?:Menlo|Monaco|Lucida Console)[^>]*>[\s\n]*(\d{6})[\s\n]*<',
                        r'>\s*(\d{6})\s*<',
                        r'(?:驗證碼|code|verification|otp)[\s\W]*(\d{6})',
                    ]
                    
                    for pattern in patterns:
                        match = re.search(pattern, content, re.I)
                        if match:
                            code = match.group(1)
                            break
        
        if code and len(code) == 6 and code.isdigit():
            print(f"[*] 收到 OTP: {code}")
            return code
        
        print(f"[*] 等待中 {attempt}/{max_attempts}...")
        time.sleep(5)
    
    print("[!] 超時，未收到 OTP")
    return ""


# ==========================================
# 密碼生成工具
# ==========================================

def generate_password() -> str:
    """生成符合 OpenAI 要求的密碼"""
    return secrets.token_urlsafe(16)[:16] + "A1"


# ==========================================
# 登入流程
# ==========================================

def run_login(
    email: str,
    password: str,
    proxy: Optional[str] = None,
    mailbox_id: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """
    執行登入流程
    
    Args:
        email: 郵箱地址
        password: 密碼
        proxy: 代理
        mailbox_id: 用於 OTP 驗證的郵箱 ID（可選）
    
    Returns:
        (token_json, "") - 成功
        (None, reason) - 失敗
    """
    def fail(reason: str) -> Tuple[Optional[str], Optional[str]]:
        return None, reason

    proxies: Optional[Dict[str, str]] = None
    if proxy:
        proxies = {"http": proxy, "https": proxy}

    s = requests.Session(proxies=proxies, impersonate="chrome")

    try:
        # Step 1: OAuth 初始化
        oauth = generate_oauth_url()
        oauth_url = oauth.auth_url
        
        print(f"[*] 初始化 OAuth 登入流程...")
        resp, current_url = _follow_redirect_chain(s, oauth_url, proxies)

        # 檢查是否直接拿到 callback
        if "code=" in current_url and "state=" in current_url:
            token_json = submit_callback_url(
                callback_url=current_url,
                expected_state=oauth.state,
                code_verifier=oauth.code_verifier,
                redirect_uri=oauth.redirect_uri,
                account_email=email,
                account_password=password,
            )
            if token_json:
                return token_json, ""
            return fail("OAuth token exchange failed")

        if not resp or resp.status_code != 200:
            print(f"[Error] 無法到達登入頁面: HTTP {resp.status_code if resp else 'None'}")
            return fail("Failed to reach login page")

        # Step 2: 提交 Email
        print(f"[*] 提交 Email: {email}")
        login_start_sentinel = _build_sentinel_header(s, "authorize_continue", proxies)
        
        login_start_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": current_url,
        }
        if login_start_sentinel:
            login_start_headers["OpenAI-Sentinel-Token"] = login_start_sentinel

        login_start_resp = s.post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers=login_start_headers,
            data=json.dumps({"username": {"value": email, "kind": "email"}}),
            proxies=proxies,
            verify=_ssl_verify(),
            timeout=15,
        )

        if login_start_resp.status_code != 200:
            message = _extract_json_error(login_start_resp)
            print(f"[Error] Email 提交失敗: {message or 'HTTP ' + str(login_start_resp.status_code)}")
            return fail(message or "Username step failed")

        try:
            login_start_data = login_start_resp.json()
        except Exception:
            print(f"[Error] Email 回應非 JSON")
            return fail("Username step returned non-JSON response")

        password_page_url = str(login_start_data.get("continue_url") or "").strip()
        if not password_page_url:
            print(f"[Error] 缺少 continue_url")
            return fail("Username step missing continue_url")

        # Step 3: 跟隨到密碼頁面
        resp, current_url = _follow_redirect_chain(s, password_page_url, proxies)
        
        if "code=" in current_url and "state=" in current_url:
            token_json = submit_callback_url(
                callback_url=current_url,
                expected_state=oauth.state,
                code_verifier=oauth.code_verifier,
                redirect_uri=oauth.redirect_uri,
                account_email=email,
                account_password=password,
            )
            if token_json:
                return token_json, password
            return None, None

        if not resp or resp.status_code != 200:
            print(f"[Error] 無法到達密碼頁面: HTTP {resp.status_code if resp else 'None'}")
            return fail("Failed to reach password page")

        # Step 4: 驗證密碼
        print(f"[*] 驗證密碼...")
        sentinel_header = _build_sentinel_header(s, "password_verify", proxies)
        password_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": current_url,
        }
        if sentinel_header:
            password_headers["OpenAI-Sentinel-Token"] = sentinel_header

        password_resp = s.post(
            "https://auth.openai.com/api/accounts/password/verify",
            headers=password_headers,
            data=json.dumps({"password": password}),
            proxies=proxies,
            verify=_ssl_verify(),
            timeout=15,
        )

        if password_resp.status_code != 200:
            message = _extract_json_error(password_resp)
            print(f"[Error] 密碼驗證失敗: {message or 'HTTP ' + str(password_resp.status_code)}")
            return fail(message or "Password verification failed")

        try:
            password_data = password_resp.json()
        except Exception:
            print(f"[Error] 密碼回應非 JSON")
            return fail("Password verification returned non-JSON response")

        next_url = _extract_next_url(password_data)
        if not next_url:
            print(f"[Error] 密碼驗證缺少 continue_url/page")
            return fail("Password verification missing continue_url/page")

        # Step 5: 跟隨後續流程
        resp, current_url = _follow_redirect_chain(s, next_url, proxies)
        
        if "code=" in current_url and "state=" in current_url:
            token_json = submit_callback_url(
                callback_url=current_url,
                expected_state=oauth.state,
                code_verifier=oauth.code_verifier,
                redirect_uri=oauth.redirect_uri,
                account_email=email,
                account_password=password,
            )
            if token_json:
                return token_json, ""

        # Step 6: 檢查是否需要 Email OTP 驗證
        if current_url.endswith("/email-verification"):
            print(f"[*] 需要 Email OTP 驗證...")
            code = get_otp_from_worker_mailbox(mailbox_id or "", proxies)
            
            if not code:
                return fail("Email verification code timeout")

            otp_resp = s.post(
                "https://auth.openai.com/api/accounts/email-otp/validate",
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Referer": current_url,
                },
                data=json.dumps({"code": code}),
                proxies=proxies,
                verify=_ssl_verify(),
                timeout=15,
            )
            
            if otp_resp.status_code != 200:
                message = _extract_json_error(otp_resp)
                return fail(message or "Email verification failed")

            try:
                otp_data = otp_resp.json()
            except Exception:
                return fail("Email verification returned non-JSON response")

            next_url = _extract_next_url(otp_data)
            if not next_url:
                return fail("Email verification missing continue_url/page")

            resp, current_url = _follow_redirect_chain(s, next_url, proxies)
            
            if "code=" in current_url and "state=" in current_url:
                token_json = submit_callback_url(
                    callback_url=current_url,
                    expected_state=oauth.state,
                    code_verifier=oauth.code_verifier,
                    redirect_uri=oauth.redirect_uri,
                    account_email=email,
                    account_password=password,
                )
                if token_json:
                    return token_json, ""

        # Step 7: Workspace 授權
        if current_url.endswith("/sign-in-with-chatgpt/codex/consent") or current_url.endswith("/workspace"):
            print(f"[*] 需要 Workspace 授權...")
            auth_cookie = s.cookies.get("oai-client-auth-session")
            if not auth_cookie:
                return fail("未能獲取到授權 Cookie")

            auth_json = _decode_jwt_segment(auth_cookie.split(".")[0])
            workspaces = auth_json.get("workspaces") or []
            if not workspaces:
                return fail("授權 Cookie 里沒有 workspace 信息")

            workspace_id = str((workspaces[0] or {}).get("id") or "").strip()
            if not workspace_id:
                return fail("無法解析 workspace_id")

            select_resp = s.post(
                "https://auth.openai.com/api/accounts/workspace/select",
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Referer": current_url,
                },
                data=json.dumps({"workspace_id": workspace_id}),
                proxies=proxies,
                verify=_ssl_verify(),
                timeout=15,
            )
            
            if select_resp.status_code != 200:
                return fail(f"選擇 workspace 失敗: HTTP {select_resp.status_code}")

            try:
                select_data = select_resp.json()
            except Exception:
                return fail("workspace/select 返回非 JSON")

            next_url = _extract_next_url(select_data)
            if not next_url:
                return fail("workspace/select 響應缺少 continue_url/page")

            _, final_url = _follow_redirect_chain(s, next_url, proxies)
            
            if "code=" in final_url and "state=" in final_url:
                token_json = submit_callback_url(
                    callback_url=final_url,
                    expected_state=oauth.state,
                    code_verifier=oauth.code_verifier,
                    redirect_uri=oauth.redirect_uri,
                    account_email=email,
                    account_password=password,
                )
                if token_json:
                    return token_json, ""

        print(f"[Error] 無法完成 OAuth 流程")
        print(f"[Debug] Final URL: {current_url}")
        return fail("Could not complete OAuth")

    except Exception as e:
        print(f"[Error] 登入流程異常: {e}")
        return None, str(e)


# ==========================================
# 註冊流程 - 降級到登入
# ==========================================

def _fallback_to_login(
    email: str,
    password: str,
    proxy: Optional[str],
    reason: str,
) -> bool:
    """
    當註冊失敗時，嘗試降級到登入流程
    不管成功或失敗，都繼續下一個新的註冊流程
    
    Args:
        email: 郵箱地址
        password: 密碼
        proxy: 代理
        reason: 降級原因（日誌用）
    
    Returns:
        True - 登入成功（獲取了 token）
        False - 登入失敗或發生異常
    """
    global _current_mailbox_id
    
    print(f"[*] === 降級到登入流程 (原因: {reason}) ===")
    print(f"[*] 使用郵箱 ID: {_current_mailbox_id}")
    
    try:
        token_json, login_reason = run_login(email, password, proxy, _current_mailbox_id)
        
        if token_json:
            print(f"[+] 降級登入成功! 保存 token...")
            # 成功就保存 token
            try:
                t_data = json.loads(token_json)
                fname_email = t_data.get("email", email).replace("@", "_")
            except Exception:
                fname_email = email.replace("@", "_") if email else "unknown"
            
            # 保存到 token 目錄
            script_dir = os.path.dirname(os.path.abspath(__file__))
            token_dir = os.path.join(script_dir, "token")
            os.makedirs(token_dir, exist_ok=True)
            
            file_name = f"token_{fname_email}_{int(time.time())}.json"
            file_path = os.path.join(token_dir, file_name)
            
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(token_json)
            print(f"[+] 降級 token 已保存: {file_path}")
            return True
        else:
            print(f"[-] 降級登入失敗: {login_reason}")
            return False
            
    except Exception as e:
        print(f"[Error] 降級登入異常: {e}")
        return False


# 全域變量：當前郵箱 ID
_current_mailbox_id = ""


def run_register(
    proxy: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    執行註冊流程
    
    Returns:
        (token_json, email, password, None) - 成功
        (None, email, password, error_reason) - 失敗但有 email/password（需外層處理降級）
        (None, None, None, error_reason) - 嚴重錯誤
    """
    global _current_mailbox_id
    
    proxies: Optional[Dict[str, str]] = None
    if proxy:
        proxies = {"http": proxy, "https": proxy}

    s = requests.Session(proxies=proxies, impersonate="chrome")

    try:
        # 網路檢查
        print(f"[*] 檢查網路環境...")
        try:
            trace = s.get("https://cloudflare.com/cdn-cgi/trace", timeout=10)
            loc_re = re.search(r"^loc=(.+)$", trace.text, re.MULTILINE)
            loc = loc_re.group(1) if loc_re else None
            print(f"[*] 當前 IP 位置: {loc}")
            if loc in ("CN", "HK"):
                raise RuntimeError("代理位置不支援")
        except Exception as e:
            print(f"[Error] 網路檢查失敗: {e}")
            return None, None, None, "網路檢查失敗"

        # Step 1: 創建郵箱
        print(f"[*] 創建 Worker 郵箱...")
        worker_email, mailbox_id = create_worker_mailbox(proxies)
        
        if worker_email and mailbox_id:
            email = worker_email
            _current_mailbox_id = mailbox_id
            print(f"[*] 使用 Worker 郵箱: {email}")
        else:
            print(f"[!] Worker 郵箱創建失敗")
            return None, None, None, "郵箱創建失敗", "網路檢查失敗"
        
        password = generate_password()
        print(f"[*] 生成的密碼: [已保存]")

        # Step 2: OAuth 初始化
        oauth = generate_oauth_url()
        oauth_url = oauth.auth_url
        
        print(f"[*] 初始化 OAuth 註冊流程...")
        resp = s.get(oauth_url, timeout=15)
        did = s.cookies.get("oai-did")
        print(f"[*] Device ID: {did}")
        
        if not did:
            print(f"[Error] 無法獲取 Device ID")
            return None, email, password, "無法獲取 Device ID"

        # Step 3: 提交 Email (Signup)
        print(f"[*] 提交 Email: {email}")
        sen_resp = requests.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            headers={
                "origin": "https://sentinel.openai.com",
                "referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6",
                "content-type": "text/plain;charset=UTF-8",
            },
            data=json.dumps({"p": "", "id": did, "flow": "authorize_continue"}),
            proxies=proxies,
            impersonate="chrome",
            timeout=15,
        )
        
        if sen_resp.status_code != 200:
            print(f"[Error] Sentinel 異常: HTTP {sen_resp.status_code}")
            return None, email, password, "Sentinel 異常"
        
        sen_token = sen_resp.json()["token"]
        sentinel = json.dumps({"p": "", "t": "", "c": sen_token, "id": did, "flow": "authorize_continue"})

        signup_body = json.dumps({"username": {"value": email, "kind": "email"}, "screen_hint": "signup"})
        signup_resp = s.post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers={
                "referer": "https://auth.openai.com/create-account",
                "accept": "application/json",
                "content-type": "application/json",
                "openai-sentinel-token": sentinel,
            },
            data=signup_body,
        )
        print(f"[*] Signup 表單狀態: {signup_resp.status_code}")

        # Step 4: 提交密碼 (Register)
        print(f"[*] 提交密碼...")
        register_body = json.dumps({"password": password, "username": email})
        
        pwd_resp = s.post(
            "https://auth.openai.com/api/accounts/user/register",
            headers={
                "referer": "https://auth.openai.com/create-account/password",
                "accept": "application/json",
                "content-type": "application/json",
                "openai-sentinel-token": sentinel,
            },
            data=register_body,
            proxies=proxies,
        )
        print(f"[*] 密碼提交狀態: {pwd_resp.status_code}")
        
        if pwd_resp.status_code != 200:
            print(f"[!] 密碼響應異常: {pwd_resp.text[:500]}")
            return None, email, password, "密碼提交失敗"

        # Step 5: 發送 OTP
        try:
            register_json = pwd_resp.json()
            register_continue = register_json.get("continue_url", "")
        except Exception:
            register_continue = ""
        
        otp_url = register_continue if register_continue else "https://auth.openai.com/api/accounts/email-otp/send"
        print(f"[*] 發送 OTP...")
        
        otp_resp = s.post(
            otp_url,
            headers={
                "referer": "https://auth.openai.com/create-account/password",
                "accept": "application/json",
                "content-type": "application/json",
                "openai-sentinel-token": sentinel,
            },
        )
        print(f"[*] OTP 發送狀態: {otp_resp.status_code}")
        
        if otp_resp.status_code not in (200, 201):
            print(f"[!] OTP 響應: {otp_resp.text[:500]}")

        # Step 6: 輪詢 OTP
        print(f"[*] 開始輪詢 Worker API 獲取 OTP (最多 75 秒)...")
        code = get_otp_from_worker_mailbox(_current_mailbox_id, proxies)
        
        # 如果首次沒拿到，進入重試
        if not code:
            print("[!] 首次輪詢超時，開始重試...")
            
            for retry in range(2):
                print(f"[*] 重發 OTP (嘗試 {retry + 1}/2)...")
                
                otp_resp = s.post(
                    "https://auth.openai.com/api/accounts/passwordless/send-otp",
                    headers={
                        "referer": "https://auth.openai.com/create-account/password",
                        "accept": "application/json",
                        "content-type": "application/json",
                    },
                )
                
                if otp_resp.status_code == 409:
                    print(f"[!] Session 已過期")
                    break
                
                if otp_resp.status_code != 200:
                    print(f"[!] OTP 重發失敗")
                    continue
                
                code = get_otp_from_worker_mailbox(_current_mailbox_id, proxies)
                if code:
                    print(f"[*] 成功獲取 OTP: {code}")
                    break
        
        if not code:
            print("[!] 未能獲取 OTP")
            return None, email, password, "OTP 獲取超時"

        # Step 7: 驗證 OTP
        print(f"[*] 驗證 OTP: {code}")
        code_resp = s.post(
            "https://auth.openai.com/api/accounts/email-otp/validate",
            headers={
                "referer": "https://auth.openai.com/email-verification",
                "accept": "application/json",
                "content-type": "application/json",
            },
            data=json.dumps({"code": code}),
        )
        print(f"[*] OTP 驗證狀態: {code_resp.status_code}")

        # Step 8: 創建帳號
        print(f"[*] 創建帳號...")
        create_account_body = json.dumps({"name": "Neo", "birthdate": "2000-02-20"})
        create_account_resp = s.post(
            "https://auth.openai.com/api/accounts/create_account",
            headers={
                "referer": "https://auth.openai.com/about-you",
                "accept": "application/json",
                "content-type": "application/json",
            },
            data=create_account_body,
        )
        create_account_status = create_account_resp.status_code
        print(f"[*] 帳號創建狀態: {create_account_status}")

        if create_account_status != 200:
            print(create_account_resp.text)
            return None, email, password, "帳號創建失敗"

        # Step 9: 檢查 Workspace
        auth_cookie = s.cookies.get("oai-client-auth-session")
        if not auth_cookie:
            print(f"[!] 未能獲取到授權 Cookie")
            return None, email, password, "無授權 Cookie"

        auth_json = _decode_jwt_segment(auth_cookie.split(".")[0])
        workspaces = auth_json.get("workspaces") or []
        
        if not workspaces:
            print(f"[!] 授權 Cookie 里沒有 workspace 信息")
            print(f"[*] 可用 keys: {list(auth_json.keys())}")
            return None, email, password, "無 workspace 信息"

        workspace_id = str((workspaces[0] or {}).get("id") or "").strip()
        if not workspace_id:
            print(f"[!] 無法解析 workspace_id")
            return None, email, password, "無法解析 workspace_id"

        # Step 10: 選擇 Workspace
        print(f"[*] 選擇 Workspace...")
        select_body = json.dumps({"workspace_id": workspace_id})
        select_resp = s.post(
            "https://auth.openai.com/api/accounts/workspace/select",
            headers={
                "referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
                "content-type": "application/json",
            },
            data=select_body,
        )

        if select_resp.status_code != 200:
            print(f"[!] 選擇 workspace 失敗: HTTP {select_resp.status_code}")
            return None, email, password, "workspace 選擇失敗"

        try:
            select_data = select_resp.json()
        except Exception:
            print(f"[!] workspace/select 響應非 JSON")
            return None, email, password, "workspace 回應解析失敗"

        continue_url = str(select_data.get("continue_url") or "").strip()
        if not continue_url:
            print(f"[!] workspace/select 響應缺少 continue_url")
            return None, email, password, "workspace 缺少 continue_url"

        # Step 11: 跟隨重定向並獲取 Token
        print(f"[*] 跟隨重定向鏈...")
        current_url = continue_url
        
        for _ in range(6):
            final_resp = s.get(current_url, allow_redirects=False, timeout=15)
            location = final_resp.headers.get("Location") or ""

            if final_resp.status_code not in [301, 302, 303, 307, 308]:
                break
            if not location:
                break

            next_url = urljoin(current_url, location)
            
            if "code=" in next_url and "state=" in next_url:
                token_json = submit_callback_url(
                    callback_url=next_url,
                    expected_state=oauth.state,
                    code_verifier=oauth.code_verifier,
                    redirect_uri=oauth.redirect_uri,
                    account_email=email,
                    account_password=password,
                )
                if token_json:
                    return token_json, email, password, None  # 成功，無錯誤
            current_url = next_url

        print(f"[!] 未能在重定向鏈中捕獲到最終 Callback URL")
        return None, email, password, "Callback URL 捕獲失敗"

    except Exception as e:
        print(f"[Error] 註冊流程異常: {e}")
        import traceback
        traceback.print_exc()
        # 發生異常時也返回錯誤
        if 'email' in dir() and 'password' in dir():
            return None, email, password, f"註冊異常: {e}"
        return None, None, None, "未知異常"


# ==========================================
# 自動模式：註冊 + 降級登入
# ==========================================

def run_auto(
    email: str,
    password: str,
    proxy: Optional[str] = None,
) -> Tuple[Optional[str], str, Optional[str]]:
    """
    自動模式：先嘗試登入，失敗則嘗試註冊
    
    Returns:
        (token_json, email, None) - 成功
        (None, email, "register_failed") - 註冊失敗
        (None, email, "login_failed") - 登入失敗
    """
    # Step 1: 先嘗試登入
    print(f"[*] === 自動模式：先嘗試登入 ===")
    token_json, reason = run_login(email, password, proxy)
    
    if token_json:
        print(f"[+] 登入成功!")
        return token_json, email, None
    
    print(f"[*] 登入失敗: {reason}")
    print(f"[*] === 自動模式：嘗試註冊 ===")
    
    # Step 2: 嘗試註冊
    # 注意：註冊模式需要新郵箱，這裡用傳入的密碼
    # 但註冊腳本會創建新郵箱，所以這裡直接返回失敗
    # 如果需要完整自動模式，需要修改為只創建郵箱然後走登入流程
    
    # 對於 auto 模式，如果登入失敗就直接返回
    return None, email, "login_failed"


# ==========================================
# 批量登入工具
# ==========================================

def load_accounts(filepath: str) -> List[Tuple[str, str]]:
    """載入帳號檔案"""
    accounts = []
    if not os.path.exists(filepath):
        print(f"[Error] 帳號檔案不存在: {filepath}")
        return accounts

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or "----" not in line:
                continue
            parts = line.split("----", 1)
            if len(parts) == 2:
                email, password = parts
                accounts.append((email.strip(), password.strip()))

    return accounts


# ==========================================
# 主入口
# ==========================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="OpenAI 自動化工具 - 整合版",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用範例:
  # 純註冊模式
  python yoyo_auto_openai_unified.py --mode register --proxy http://127.0.0.1:7890

  # 純登入模式
  python yoyo_auto_openai_unified.py --mode login --accounts qzz-accounts.txt --proxy http://127.0.0.1:7890

  # 自動模式（先登入，失敗則嘗試其他方式）
  python yoyo_auto_openai_unified.py --mode auto --proxy http://127.0.0.1:7890
        """
    )
    parser.add_argument(
        "--mode",
        type=str,
        choices=["login", "register", "auto"],
        default="register",
        help="運行模式: login(純登入), register(純註冊), auto(自動)"
    )
    parser.add_argument("--proxy", default=None, help="代理地址，如 http://127.0.0.1:7890")
    parser.add_argument("--accounts", default=ACCOUNTS_FILE, help="帳號檔案路徑 (login 模式)")
    parser.add_argument("--once", action="store_true", help="只運行一次 (register 模式)")
    parser.add_argument("--sleep-min", type=int, default=5, help="循環模式最短等待秒數")
    parser.add_argument("--sleep-max", type=int, default=30, help="循環模式最長等待秒數")
    
    args = parser.parse_args()

    sleep_min = max(1, args.sleep_min)
    sleep_max = max(sleep_min, args.sleep_max)
    run_ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # 設置結果輸出目錄
    result_base_dir = TOKEN_OUTPUT_DIR if TOKEN_OUTPUT_DIR and os.path.isdir(TOKEN_OUTPUT_DIR) else os.getcwd()
    result_files = _result_file_paths(result_base_dir, run_ts)
    
    for path in result_files.values():
        with open(path, "w", encoding="utf-8"):
            pass

    print(f"[*] OpenAI 自動化工具 v3.7 整合版")
    print(f"[*] 模式: {args.mode}")
    print(f"[*] 結果目錄: {result_base_dir}")

    if args.mode == "register":
        # 純註冊模式
        _run_register_mode(args, result_files, sleep_min, sleep_max, run_ts)
        
    elif args.mode == "login":
        # 純登入模式
        _run_login_mode(args, result_files, sleep_min, sleep_max, run_ts)
        
    elif args.mode == "auto":
        # 自動模式
        _run_auto_mode(args, result_files, sleep_min, sleep_max, run_ts)


def _run_register_mode(args, result_files, sleep_min, sleep_max, run_ts):
    """純註冊模式 - 永不停歇，永遠繼續下一輪"""
    count = 0
    
    while True:
        count += 1
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] >>> 開始第 {count} 次註冊 <<<")

        try:
            token_json, email, password, error_reason = run_register(args.proxy)

            if token_json:
                # ✅ 註冊成功！保存 token，不執行降級
                try:
                    t_data = json.loads(token_json)
                    fname_email = t_data.get("email", "unknown").replace("@", "_")
                except Exception:
                    fname_email = email.replace("@", "_") if email else "unknown"

                _save_token(token_json, fname_email, result_files["success"])
                print(f"[+] 註冊成功! Token 已保存")
            else:
                # ❌ 註冊失敗，執行降級登入
                print(f"[*] 註冊失敗: {error_reason or '未知錯誤'}")
                if email:
                    _append_line(result_files["other_fail"], f"{email}----{password or ''}\t{error_reason or '註冊失敗'}")
                
                # 執行降級登入（不論成功失敗都繼續）
                _fallback_to_login(email, password, args.proxy, error_reason or "註冊失敗")

        except Exception as e:
            print(f"[Error] 發生未捕獲異常: {e}")

        if args.once:
            break

        # 無論成功或失敗，永遠繼續下一輪
        wait_time = random.randint(sleep_min, sleep_max)
        print(f"[*] 休息 {wait_time} 秒，繼續下一個...")
        time.sleep(wait_time)


def _run_login_mode(args, result_files, sleep_min, sleep_max, run_ts):
    """純登入模式"""
    accounts = load_accounts(args.accounts)
    if not accounts:
        print("[Error] 未找到有效帳號")
        return

    print(f"[*] 載入了 {len(accounts)} 個帳號")

    success_count = 0
    fail_count = 0

    for idx, (email, password) in enumerate(accounts, 1):
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] >>> 處理第 {idx}/{len(accounts)} 個帳號: {email} <<<")

        token_json, reason = run_login(email, password, args.proxy)

        if token_json:
            try:
                t_data = json.loads(token_json)
                token_email = t_data.get("email", email)
                fname_email = token_email.replace("@", "_")
                
                _save_token(token_json, fname_email, result_files["success"])
                success_count += 1
            except Exception as e:
                print(f"[-] 保存 token 失敗: {e}")
                _append_line(result_files["other_fail"], f"{email}----{password}\t保存失敗: {e}")
                fail_count += 1
        else:
            print(f"[-] 登入失敗: {reason}")
            category = _categorize_failure(reason or "")
            _append_line(result_files[category], f"{email}----{password}\t{reason or '未知失敗'}")
            fail_count += 1

        if idx < len(accounts):
            wait_time = random.randint(sleep_min, sleep_max)
            print(f"[*] 等待 {wait_time} 秒...")
            time.sleep(wait_time)

    print(f"\n[*] 批量登入完成. 成功: {success_count}, 失敗: {fail_count}, 總計: {len(accounts)}")


def _run_auto_mode(args, result_files, sleep_min, sleep_max, run_ts):
    """自動模式：支援批量帳號，先嘗試登入"""
    # Auto 模式需要帳號檔案
    accounts = load_accounts(args.accounts)
    if not accounts:
        print("[Error] 自動模式需要帳號檔案")
        return

    print(f"[*] 載入了 {len(accounts)} 個帳號")

    success_count = 0
    fail_count = 0

    for idx, (email, password) in enumerate(accounts, 1):
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] >>> 處理第 {idx}/{len(accounts)} 個帳號: {email} <<<")

        token_json, result_email, fail_reason = run_auto(email, password, args.proxy)

        if token_json:
            try:
                t_data = json.loads(token_json)
                token_email = t_data.get("email", email)
                fname_email = token_email.replace("@", "_")
                
                _save_token(token_json, fname_email, result_files["success"])
                success_count += 1
            except Exception as e:
                print(f"[-] 保存 token 失敗: {e}")
                _append_line(result_files["other_fail"], f"{email}----{password}\t保存失敗: {e}")
                fail_count += 1
        else:
            print(f"[-] 處理失敗: {fail_reason}")
            category = _categorize_failure(fail_reason or "")
            _append_line(result_files[category], f"{email}----{password}\t{fail_reason or '未知失敗'}")
            fail_count += 1

        if idx < len(accounts):
            wait_time = random.randint(sleep_min, sleep_max)
            print(f"[*] 等待 {wait_time} 秒...")
            time.sleep(wait_time)

    print(f"\n[*] 自動模式完成. 成功: {success_count}, 失敗: {fail_count}, 總計: {len(accounts)}")


def _save_token(token_json: str, fname_email: str, success_file: str) -> str:
    """保存 Token 到檔案"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    token_dir = os.path.join(script_dir, "token")
    
    try:
        os.makedirs(token_dir, exist_ok=True)
        file_name = f"token_{fname_email}_{int(time.time())}.json"
        file_path = os.path.join(token_dir, file_name)
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(token_json)
        
        print(f"[+] Token 已保存: {file_path}")
        _append_line(success_file, f"{fname_email}\t{file_path}")
        return file_path
    except Exception as e:
        print(f"[Warn] 保存 Token 失敗: {e}")
        return ""


if __name__ == "__main__":
    main()
