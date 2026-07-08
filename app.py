#!/usr/bin/env python3

import os
import sys
import base64
import json
import time
import subprocess
import requests
import traceback
from datetime import datetime, timezone, timedelta
from playwright.sync_api import sync_playwright

# 环境变量配置(私库可直接在双引号内填写,session建议填写secrets,需要自动更新)
# --- 多账号模式 ---
# 设置 ACCOUNTS 环境变量即可启用多账号，支持两种写法（任选其一）：
#
# 写法一（推荐，纯文本，避免 JSON 转义麻烦）：每行一个账号，用冒号分隔
#   USER_ID:SESSION:SECRET_NAME
#   SECRET_NAME 可省略，省略时自动使用 SESSION_1 / SESSION_2 ... 作为该账号
#   Session 过期后自动更新的 GitHub Secret 名称。示例：
#
#   ACCOUNTS = """
#   123456:xxxxxxxxxxxxxxxxxxxxx:SESSION_1
#   234567:yyyyyyyyyyyyyyyyyyyyy:SESSION_2
#   """
#
# 写法二：JSON 数组
#   ACCOUNTS = [{"user_id":"123456","session":"xxx","secret_name":"SESSION_1"},
#               {"user_id":"234567","session":"yyy","secret_name":"SESSION_2"}]
#
# --- 单账号模式（兼容旧配置，不设置 ACCOUNTS 时生效）---
USER_ID      = os.getenv("USER_ID") or ""  # 用户ID,必填,登录后右上角个人设置里进去就看到ID了,一般是6位数
SESSION      = os.getenv("SESSION") or ""  # session必填,登录后F12或右键检查菜单进去,选择应用程序或Appcations栏,找到cookie,右边找到session的值
ACCOUNTS_RAW = os.getenv("ACCOUNTS") or ""  # 多账号配置，见上方说明
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN") or ""  # Telegram bot token,不需要通知可以留空
TG_CHAT_ID   = os.getenv("TG_CHAT_ID") or ""    # Telegram chat id

SITE_URL = "https://anyrouter.top"
SESSION_TTL_DAYS = 30  # Session 有效期 30 天，剩余 < 3 天则更新
SESSION_THRESHOLD_DAYS = 3
QUOTA_PER_DOLLAR = 500000 
WAF_COOKIE_NAMES = ["acw_tc", "cdn_sec_tc", "acw_sc__v2"]

# 工具函数
def log(level: str, msg: str):
    """带时间戳的日志输出"""
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)

def decode_session_timestamp(session_value: str) -> int | None:
    if not session_value:
        return None

    # 策略 1：直接按 | 分割（gorilla securecookie 标准格式）
    parts = session_value.split("|")
    if parts and parts[0].strip().isdigit():
        return int(parts[0].strip())

    # 策略 2：可能是 URL 编码的 |（%7C）
    if "%7C" in session_value or "%7c" in session_value:
        decoded_url = session_value.replace("%7C", "|").replace("%7c", "|")
        parts = decoded_url.split("|")
        if parts and parts[0].strip().isdigit():
            return int(parts[0].strip())

    # 策略 3：整体 base64 编码的情况（某些部署可能额外编码了一层）
    try:
        padded = session_value + "=" * (4 - len(session_value) % 4) if len(session_value) % 4 else session_value
        try:
            decoded = base64.urlsafe_b64decode(padded)
        except Exception:
            decoded = base64.b64decode(padded)
        decoded_str = decoded.decode("utf-8", errors="ignore")
        parts = decoded_str.split("|")
        if parts and parts[0].strip().isdigit():
            return int(parts[0].strip())
    except Exception:
        pass

    return None

def check_session_expiry(session_value: str):
    timestamp = decode_session_timestamp(session_value)
    if not timestamp:
        log("WARN", "无法解码 Session 时间戳，跳过期检查")
        return None, False

    created_time = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    expiry_time = created_time + timedelta(days=SESSION_TTL_DAYS)
    now = datetime.now(tz=timezone.utc)

    remaining = expiry_time - now
    remaining_days = remaining.total_seconds() / 86400

    created_local = created_time.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    expiry_local = expiry_time.astimezone().strftime("%Y-%m-%d %H:%M:%S")

    log("INFO", f"Session 创建时间: {created_local}")
    log("INFO", f"Session 过期时间: {expiry_local}")
    log("INFO", f"剩余有效时间: {remaining_days:.2f} 天")

    need_update = remaining_days < SESSION_THRESHOLD_DAYS
    if need_update:
        log("WARN", f"Session 剩余 {remaining_days:.2f} 天 < {SESSION_THRESHOLD_DAYS} 天，需要更新！")

    return remaining_days, need_update

def parse_accounts() -> list[dict]:
    """
    解析多账号配置。优先读取 ACCOUNTS 环境变量，
    支持 "USER_ID:SESSION:SECRET_NAME" 逐行格式，也支持 JSON 数组格式。
    未设置 ACCOUNTS 时，退化为单账号模式（读取 USER_ID / SESSION）。

    返回: [{"user_id": str, "session": str, "secret_name": str}, ...]
    """
    accounts: list[dict] = []

    raw = ACCOUNTS_RAW.strip()
    if raw:
        # 尝试 JSON 数组格式
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                for idx, item in enumerate(parsed, start=1):
                    uid = str(item.get("user_id", "")).strip()
                    sess = str(item.get("session", "")).strip()
                    secret_name = str(item.get("secret_name") or f"SESSION_{idx}").strip()
                    if uid and sess:
                        accounts.append({"user_id": uid, "session": sess, "secret_name": secret_name})
                if accounts:
                    return accounts
        except (json.JSONDecodeError, AttributeError, TypeError):
            pass

        # 逐行 "USER_ID:SESSION:SECRET_NAME" 格式
        for idx, line in enumerate(raw.splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(":")]
            if len(parts) < 2:
                log("WARN", f"ACCOUNTS 第 {idx} 行格式不正确，已跳过: {line}")
                continue
            uid, sess = parts[0], parts[1]
            secret_name = parts[2] if len(parts) >= 3 and parts[2] else f"SESSION_{idx}"
            if uid and sess:
                accounts.append({"user_id": uid, "session": sess, "secret_name": secret_name})

        if accounts:
            return accounts
        log("WARN", "ACCOUNTS 环境变量已设置但未解析出有效账号，回退到单账号模式")

    # 单账号模式（兼容旧配置）
    if USER_ID and SESSION:
        accounts.append({"user_id": USER_ID, "session": SESSION, "secret_name": "SESSION"})

    return accounts

def update_github_secret(secret_name: str, new_value: str) -> bool:
    """通过 gh CLI 更新 GitHub Actions Secret"""
    if not new_value:
        log("WARN", f"跳过更新 {secret_name}：新值为空")
        return False

    masked = new_value[:4] + "..." + new_value[-4:] if len(new_value) > 8 else "***"
    log("INFO", f"🔄 更新 Secret: {secret_name} (新值: {masked})")

    try:
        proc = subprocess.run(
            ["gh", "secret", "set", secret_name, "--body", new_value],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if proc.returncode == 0:
            log("INFO", f"✅ {secret_name} 更新成功")
            return True
        else:
            log("ERROR", f"更新失败: {proc.stderr.strip()}")
            return False
    except Exception as e:
        log("ERROR", f"异常: {e}")
        return False

def send_telegram(message: str) -> bool:
    """发送 Telegram 消息"""
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        log("WARN", "Telegram 配置不完整，跳过发送")
        print(f"--- 消息内容 ---\n{message}\n---------------")
        return False

    try:
        url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
        data = {
            "chat_id": TG_CHAT_ID,
            "text": message,
            "parse_mode": "HTML",
        }
        resp = requests.post(url, json=data, timeout=30)
        resp.raise_for_status()
        log("INFO", "Telegram 消息发送成功")
        return True
    except Exception as e:
        log("ERROR", f"Telegram 发送失败: {e}")
        return False

# WAF Cookie 获取
def get_waf_cookies() -> dict:
    """
    使用 Playwright 浏览器访问登录页面，获取 WAF Cookie。
    WAF Cookie 包括: acw_tc, cdn_sec_tc, acw_sc__v2
    """
    log("INFO", f"使用浏览器获取 WAF Cookie（访问 {SITE_URL}/login）...")

    waf_cookies = {}

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        )

        context = browser.new_context(
            viewport={"width": 1280, "height": 720},
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
            ),
        )

        page = context.new_page()

        try:
            page.goto(f"{SITE_URL}/login", wait_until="domcontentloaded", timeout=30000)
        except Exception as e:
            log("WARN", f"访问登录页面失败: {e}")

        # 等待 WAF Cookie 生成
        page.wait_for_timeout(3000)

        cookies = context.cookies()
        for cookie in cookies:
            name = cookie.get("name")
            value = cookie.get("value")
            if name in WAF_COOKIE_NAMES and value:
                waf_cookies[name] = value

        browser.close()

    if waf_cookies:
        log("INFO", f"获取到 {len(waf_cookies)} 个 WAF Cookie: {list(waf_cookies.keys())}")
    else:
        log("WARN", "未获取到 WAF Cookie")

    return waf_cookies

# API 调用
def build_headers(user_id: str) -> dict:
    """构建 API 请求头"""
    return {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
        ),
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Referer": SITE_URL,
        "Origin": SITE_URL,
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "new-api-user": user_id,
    }

def get_user_info(session: requests.Session, headers: dict) -> dict | None:
    """
    通过 /api/user/self 接口获取用户信息。
    返回:
      {
        "quota": int,           # 剩余 quota
        "used_quota": int,      # 已使用 quota
        "username": str,        # 用户名
        "id": int,              # 用户 ID
        "raw": dict,            # 原始数据
      }
    """
    url = f"{SITE_URL}/api/user/self"
    try:
        resp = session.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("success"):
                user_data = data.get("data", {})
                return {
                    "quota": user_data.get("quota", 0),
                    "used_quota": user_data.get("used_quota", 0),
                    "username": user_data.get("username", ""),
                    "id": user_data.get("id", 0),
                    "raw": user_data,
                }
            else:
                log("WARN", f"API 返回非成功: {data}")
        else:
            log("WARN", f"API HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        log("WARN", f"获取用户信息失败: {e}")

    return None

def do_check_in(session: requests.Session, headers: dict) -> bool:
    """
    调用签到接口 POST /api/user/sign_in
    """
    url = f"{SITE_URL}/api/user/sign_in"

    checkin_headers = headers.copy()
    checkin_headers["Content-Type"] = "application/json"
    checkin_headers["X-Requested-With"] = "XMLHttpRequest"

    try:
        resp = session.post(url, headers=checkin_headers, timeout=30)
        log("INFO", f"签到接口响应: HTTP {resp.status_code}")

        if resp.status_code == 200:
            try:
                result = resp.json()
                if result.get("ret") == 1 or result.get("code") == 0 or result.get("success"):
                    log("INFO", "✅ 签到成功！")
                    return True
                else:
                    error_msg = result.get("msg", result.get("message", "Unknown error"))
                    already_keywords = ["已经签到", "已签到", "重复签到", "already checked", "already signed"]
                    if any(kw in str(error_msg).lower() for kw in already_keywords):
                        log("INFO", "今日已签到过")
                        return True
                    log("WARN", f"签到失败: {error_msg}")
                    return False
            except json.JSONDecodeError:
                if "success" in resp.text.lower():
                    log("INFO", "✅ 签到成功！")
                    return True
                log("WARN", f"签到响应格式异常: {resp.text[:200]}")
                return False
        else:
            log("WARN", f"签到失败: HTTP {resp.status_code}: {resp.text[:200]}")
            return False
    except Exception as e:
        log("ERROR", f"签到请求异常: {e}")
        return False

def format_balance(quota: int) -> str:
    """将 quota 转换为美元显示"""
    if quota is None:
        return "N/A"
    balance = quota / QUOTA_PER_DOLLAR
    if balance == int(balance):
        return f"{int(balance)}$"
    return f"{balance:.2f}$"

# 主流程
def run_checkin_for_account(account: dict, waf_cookies: dict, now_str: str) -> str:
    """
    对单个账号执行完整的签到流程，返回该账号在汇总 Telegram 消息中的一段文本。
    出错时不抛异常中断整体流程，而是返回错误说明，方便多账号互不影响。
    """
    user_id = account["user_id"]
    session_value = account["session"]
    secret_name = account["secret_name"]

    log("INFO", "-" * 50)
    log("INFO", f"开始处理账号 用户 ID: {user_id} (Secret: {secret_name})")

    if not session_value:
        log("ERROR", f"账号 {user_id} 的 SESSION 未配置")
        return f"❌ 账户 {user_id}：SESSION 未配置\n"

    # ---------- 构建 HTTP Session ----------
    http_session = requests.Session()

    all_cookies = {}
    all_cookies.update(waf_cookies)
    all_cookies["session"] = session_value
    all_cookies["user_id"] = user_id

    for name, value in all_cookies.items():
        http_session.cookies.set(name, value, domain="anyrouter.top", path="/")

    log("INFO", f"已设置 {len(all_cookies)} 个 Cookie: {list(all_cookies.keys())}")

    headers = build_headers(user_id)

    # ---------- 验证登录状态并获取初始余额 ----------
    log("INFO", "通过 API 验证登录状态...")
    user_info_1 = get_user_info(http_session, headers)

    if not user_info_1:
        log("ERROR", f"账号 {user_id} API 验证失败，Session 可能已过期")
        return (
            f"❌ <b>账户 {user_id} 登录失败</b>\n"
            f"📝 原因: Session 已过期，请尽快更新 {secret_name}\n"
        )

    log("INFO", "✅ 登录成功！（API 验证通过）")
    username = user_info_1.get("username", "")
    log("INFO", f"用户名: {username}")

    first_balance = format_balance(user_info_1.get("quota", 0))
    log("INFO", f"初始余额: {first_balance}")
    log("INFO", f"API Quota: {user_info_1.get('quota')}, Used: {user_info_1.get('used_quota')}")

    # ---------- 签到领币 ----------
    log("INFO", "执行签到领币...")
    do_check_in(http_session, headers)

    # ---------- 等待后重新获取余额 ----------
    log("INFO", "等待 3 秒后重新获取余额...")
    time.sleep(3)

    user_info_2 = get_user_info(http_session, headers)
    second_balance = format_balance(user_info_2.get("quota", 0)) if user_info_2 else "N/A"
    log("INFO", f"刷新后余额: {second_balance}")
    if user_info_2:
        log("INFO", f"API Quota: {user_info_2.get('quota')}, Used: {user_info_2.get('used_quota')}")

    balance_changed = first_balance != second_balance
    if balance_changed:
        log("INFO", f"✅ 余额发生变化: {first_balance} → {second_balance}")
    else:
        log("INFO", f"余额未变化: {first_balance}")

    # ---------- 检查 Session 有效期 ----------
    remaining_days, need_update = check_session_expiry(session_value)

    session_status = ""
    if need_update:
        log("WARN", f"账号 {user_id} 的 Session 即将过期，尝试更新 GitHub Secret {secret_name}...")
        success = update_github_secret(secret_name, session_value)
        if success:
            session_status = f"✅ Session 已自动更新（剩余 {remaining_days:.1f} 天）" if remaining_days else "✅ Session 已自动更新"
        else:
            session_status = f"⚠️ Session 剩余 {remaining_days:.1f} 天，Secret 更新失败，请手动更新" if remaining_days else "⚠️ Session 需手动更新"
    else:
        if remaining_days is not None:
            session_status = f"✅ Session 有效（剩余 {remaining_days:.1f} 天）"
        else:
            session_status = "⚠️ Session 有效期未知"

    return (
        f"👤 账户: {user_id}" + (f" ({username})" if username else "") + "\n"
        f"💰 签到前: {first_balance}  →  签到后: {second_balance}\n"
        f"📋 {session_status}\n"
    )

def run_checkin():
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    accounts = parse_accounts()

    log("INFO", "=" * 50)
    log("INFO", "Anyrouter 领币脚本启动")
    log("INFO", f"时间: {now_str}")
    log("INFO", f"账号数量: {len(accounts)}")
    log("INFO", "=" * 50)

    if not accounts:
        log("ERROR", "未配置任何账号，请设置 ACCOUNTS（多账号）或 USER_ID / SESSION（单账号）")
        send_telegram(
            f"❌ <b>Anyrouter 脚本配置错误</b>\n"
            f"⏱️ 时间: {now_str}\n"
            f"📝 原因: 未配置任何账号，请检查 ACCOUNTS 或 USER_ID / SESSION"
        )
        sys.exit(1)

    # ---------- 获取 WAF Cookie（所有账号共用，只需获取一次） ----------
    waf_cookies = get_waf_cookies()

    sections = []
    for account in accounts:
        try:
            sections.append(run_checkin_for_account(account, waf_cookies, now_str))
        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"
            log("ERROR", f"账号 {account.get('user_id')} 处理异常: {error_msg}")
            log("ERROR", traceback.format_exc())
            sections.append(f"❌ 账户 {account.get('user_id')} 处理异常: {error_msg}\n")

    # ---------- 发送汇总 Telegram 通知 ----------
    header = "🎁 <b>Anyrouter 签到通知</b>" if len(accounts) == 1 else f"🎁 <b>Anyrouter 签到通知</b>（共 {len(accounts)} 个账号）"
    message = header + f"\n⏱️ 时间: {now_str}\n\n" + "\n".join(sections)

    send_telegram(message)

    log("INFO", "=== 脚本执行完毕 ===")

def main():
    try:
        run_checkin()
    except KeyboardInterrupt:
        log("WARN", "用户中断")
        sys.exit(130)
    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        log("ERROR", f"脚本执行出错: {error_msg}")
        log("ERROR", traceback.format_exc())
        send_telegram(
            f"❌ <b>Anyrouter 脚本异常</b>\n"
            f"⏱️ 时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"📝 错误: {error_msg}"
        )
        sys.exit(1)

if __name__ == "__main__":
    main()
