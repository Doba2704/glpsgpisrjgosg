#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  TITAN v5.0 ULTRA — Secured Edition                                         ║
║  + Telegram PIN Auth (кожен вхід → PIN у Telegram)                          ║
║  + Session management + IP blocking + Rate limiting                         ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

# ======================== ІМПОРТИ (без дублів) ========================
import sys
import os
import hashlib
import time
import threading
import ctypes
import shutil
import subprocess
import json
import getpass
import platform
import uuid
import re
import asyncio
import sqlite3
import smtplib
import random
import io
import secrets
import traceback
from collections import deque, defaultdict
from urllib.parse import urlparse
from datetime import datetime, timedelta
from typing import Optional, Any, Dict, List, Tuple

import requests
import dns.resolver
import pandas as pd
import nest_asyncio
import streamlit as st
import os
# Завантажуємо браузер для Playwright при запуску на Streamlit Cloud
if not os.path.exists("/home/appuser/.cache/ms-playwright"):
    os.system("playwright install chromium")
    os.system("playwright install-deps")
from playwright.async_api import async_playwright
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

nest_asyncio.apply()

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

# ════════════════════════════════════════════════════
#  КОНФІГУРАЦІЯ — ЗАПОВНІТЬ ПЕРЕД ДЕПЛОЄМ
# ════════════════════════════════════════════════════
TELEGRAM_BOT_TOKEN = os.environ.get("7834347258:AAGXPDoyemyNvfOqoZBeEB_5PFYNB7aRrDw", "YOUR_BOT_TOKEN")
TELEGRAM_CHAT_ID   = os.environ.get("1913057855",   "YOUR_CHAT_ID")

# Час дії PIN (секунди)
PIN_TTL_SECONDS  = 60   # 1 хвилина
# Максимум невдалих спроб перед блокуванням IP
MAX_FAILED_TRIES = 3
# Час блокування IP (секунди)
IP_BAN_SECONDS   = 3600   # 60 хвилин
# Сесія дійсна N хвилин після входу
SESSION_TTL_MIN  = 240   # 2 години

# ════════════════════════════════════════════════════════════
#  ЗБЕРІГАННЯ СЕСІЙ / ПІНІВ / БАНІВ (в пам'яті + файл)
# ════════════════════════════════════════════════════════════
_AUTH_LOCK = threading.Lock()

# { ip: {"pin": "...", "expires": datetime, "tries": int} }
_pending_pins: Dict[str, dict] = {}
# { ip: datetime }  — коли закінчується бан
_banned_ips: Dict[str, datetime] = {}
# { session_token: {"ip": ..., "expires": datetime} }
_active_sessions: Dict[str, dict] = {}
# { ip: int }  — лічильник невдалих спроб
_fail_count: Dict[str, int] = defaultdict(int)

# ─────────── Telegram helpers ───────────────────────────────
def _tg_send(text: str) -> bool:
    """Відправляє повідомлення в Telegram."""
    if not TELEGRAM_BOT_TOKEN or TELEGRAM_BOT_TOKEN == "YOUR_BOT_TOKEN":
        return False
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        r = requests.post(url, json={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": text,
            "parse_mode": "HTML"
        }, timeout=10)
        return r.status_code == 200
    except Exception:
        return False

def _get_client_ip() -> str:
    """Витягує IP клієнта з Streamlit headers."""
    try:
        headers = st.context.headers
        # За проксі (Nginx / Cloudflare)
        for h in ("X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"):
            val = headers.get(h, "")
            if val:
                return val.split(",")[0].strip()
    except Exception:
        pass
    return "unknown"

def _geo_lookup(ip: str) -> str:
    """Швидкий гео-пошук через ip-api."""
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city,isp",
                         timeout=5)
        if r.status_code == 200:
            d = r.json()
            return f"{d.get('city','?')}, {d.get('country','?')} | {d.get('isp','?')}"
    except Exception:
        pass
    return "geo unknown"

# ─────────── PIN генерація і верифікація ────────────────────
def generate_and_send_pin(ip: str) -> bool:
    """Генерує 6-значний PIN, зберігає, відправляє в Telegram."""
    pin = str(secrets.randbelow(900000) + 100000)  # 100000–999999
    expires = datetime.now() + timedelta(seconds=PIN_TTL_SECONDS)
    geo = _geo_lookup(ip)
    with _AUTH_LOCK:
        _pending_pins[ip] = {"pin": pin, "expires": expires}

    msg = (
        f"🔐 <b>TITAN — Новий вхід</b>\n\n"
        f"🌐 IP: <code>{ip}</code>\n"
        f"📍 Гео: {geo}\n"
        f"🕐 Час: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"🔑 PIN-код: <b><code>{pin}</code></b>\n"
        f"⏳ Дійсний {PIN_TTL_SECONDS // 60} хв\n\n"
        f"Якщо це не ви — заблокуйте IP!"
    )
    return _tg_send(msg)

def verify_pin(ip: str, entered: str) -> Tuple[bool, str]:
    """
    Перевіряє PIN.
    Повертає (success, reason).
    """
    # Перевіряємо бан
    with _AUTH_LOCK:
        ban_until = _banned_ips.get(ip)
    if ban_until and datetime.now() < ban_until:
        remaining = int((ban_until - datetime.now()).total_seconds())
        return False, f"IP заблоковано ще на {remaining} сек"

    with _AUTH_LOCK:
        data = _pending_pins.get(ip)

    if not data:
        return False, "PIN не знайдено — запросіть новий"

    if datetime.now() > data["expires"]:
        with _AUTH_LOCK:
            _pending_pins.pop(ip, None)
        return False, "PIN прострочено — запросіть новий"

    if entered.strip() != data["pin"]:
        _fail_count[ip] += 1
        if _fail_count[ip] >= MAX_FAILED_TRIES:
            ban_until = datetime.now() + timedelta(seconds=IP_BAN_SECONDS)
            with _AUTH_LOCK:
                _banned_ips[ip] = ban_until
                _pending_pins.pop(ip, None)
            _tg_send(
                f"🚨 <b>TITAN — IP ЗАБЛОКОВАНО</b>\n"
                f"IP <code>{ip}</code> зробив {MAX_FAILED_TRIES} невдалих спроб входу!\n"
                f"Заблоковано на {IP_BAN_SECONDS // 60} хв."
            )
            return False, f"Забагато спроб — IP заблоковано на {IP_BAN_SECONDS // 60} хв"
        remaining = MAX_FAILED_TRIES - _fail_count[ip]
        return False, f"Невірний PIN. Залишилось спроб: {remaining}"

    # PIN вірний
    _fail_count[ip] = 0
    with _AUTH_LOCK:
        _pending_pins.pop(ip, None)
    return True, "OK"

def create_session(ip: str) -> str:
    """Створює токен сесії для авторизованого IP."""
    token = secrets.token_hex(32)
    expires = datetime.now() + timedelta(minutes=SESSION_TTL_MIN)
    with _AUTH_LOCK:
        _active_sessions[token] = {"ip": ip, "expires": expires}
    return token

def check_session(token: str, ip: str) -> bool:
    """Перевіряє чи сесія дійсна."""
    if not token:
        return False
    with _AUTH_LOCK:
        sess = _active_sessions.get(token)
    if not sess:
        return False
    if datetime.now() > sess["expires"]:
        with _AUTH_LOCK:
            _active_sessions.pop(token, None)
        return False
    # IP прив'язка (захист від крадіжки токена)
    if sess["ip"] != ip and ip != "unknown":
        return False
    return True

def cleanup_expired():
    """Прибирає прострочені записи (фоновий потік)."""
    while True:
        now = datetime.now()
        with _AUTH_LOCK:
            for ip in list(_pending_pins):
                if now > _pending_pins[ip]["expires"]:
                    del _pending_pins[ip]
            for ip in list(_banned_ips):
                if now > _banned_ips[ip]:
                    del _banned_ips[ip]
            for tok in list(_active_sessions):
                if now > _active_sessions[tok]["expires"]:
                    del _active_sessions[tok]
        time.sleep(60)

threading.Thread(target=cleanup_expired, daemon=True).start()

# ─────────── Streamlit Auth Gate ────────────────────────────
def render_auth_screen(ip: str):
    """Рендерить екран авторизації через PIN."""
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=Inter:wght@400;600&display=swap');
    .stApp { background: radial-gradient(circle at 10% 20%, #0a0f1e, #030712); }
    </style>
    """, unsafe_allow_html=True)

    col = st.columns([1, 2, 1])[1]
    with col:
        st.markdown("""
        <div style="text-align:center;margin:60px 0 30px">
            <div style="font-family:Orbitron,sans-serif;font-size:2rem;font-weight:900;
                        background:linear-gradient(90deg,#e879f9,#60a5fa,#34d399);
                        -webkit-background-clip:text;-webkit-text-fill-color:transparent">
                🔱 TITAN v5.0
            </div>
            <div style="color:#94a3b8;margin-top:8px;font-size:0.9rem">
                Захищений доступ — потрібна авторизація
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Ініціалізація стану авторизації
        if "auth_pin_sent" not in st.session_state:
            st.session_state.auth_pin_sent = False
        if "auth_session" not in st.session_state:
            st.session_state.auth_session = ""

        # Перевірка бану
        with _AUTH_LOCK:
            ban = _banned_ips.get(ip)
        if ban and datetime.now() < ban:
            remaining = int((ban - datetime.now()).total_seconds())
            st.error(f"🚫 Ваш IP заблоковано на {remaining} сек через підозрілу активність")
            st.stop()

        if not st.session_state.auth_pin_sent:
            st.info(f"🌐 Ваш IP: `{ip}`")
            st.markdown("Натисніть кнопку — PIN надійде у Telegram власника системи.")

            if st.button("📲 Надіслати PIN в Telegram", type="primary", use_container_width=True):
                with st.spinner("Відправляємо PIN..."):
                    ok = generate_and_send_pin(ip)
                if ok:
                    st.session_state.auth_pin_sent = True
                    st.success("✅ PIN відправлено! Введіть його нижче.")
                    st.rerun()
                else:
                    st.error("❌ Telegram недоступний. Перевірте налаштування бота.")
        else:
            st.success("📲 PIN надіслано в Telegram")
            pin_input = st.text_input(
                "Введіть 6-значний PIN",
                max_chars=6,
                placeholder="123456",
                type="password"
            )
            col_a, col_b = st.columns(2)
            with col_a:
                if st.button("✅ Підтвердити", type="primary", use_container_width=True):
                    ok, reason = verify_pin(ip, pin_input)
                    if ok:
                        token = create_session(ip)
                        st.session_state.auth_session = token
                        _tg_send(
                            f"✅ <b>TITAN — Успішний вхід</b>\n"
                            f"IP: <code>{ip}</code>\n"
                            f"Час: {datetime.now().strftime('%H:%M:%S')}"
                        )
                        st.success("✅ Авторизовано!")
                        time.sleep(0.5)
                        st.rerun()
                    else:
                        st.error(f"❌ {reason}")
            with col_b:
                if st.button("🔄 Новий PIN", use_container_width=True):
                    st.session_state.auth_pin_sent = False
                    st.rerun()

        st.stop()  # Зупиняємо рендер основного додатку

# ─────────── Головний auth check ────────────────────────────
def require_auth():
    """Виклик на початку кожного рендеру."""
    ip = _get_client_ip()
    token = st.session_state.get("auth_session", "")
    if not check_session(token, ip):
        render_auth_screen(ip)

# ======================== КОНФІГУРАЦІЯ TITAN ========================
DEFAULT_PARALLEL = 30
DEFAULT_SCRAPE_DEPTH = 6000
DEFAULT_MIN_SCORE = 80
DB_PATH = "titan_ultra.db"
BASE_WEBHOOK_URL = "https://your-crm.com/api/leads"
GLOBAL_API_KEY = ""

# ======================== ІНІЦІАЛІЗАЦІЯ СЕСІЇ ========================
def _init_state():
    defaults = {
        "logs": [],
        "running": False,
        "stats": {"total": 0, "diamonds": 0, "whales": 0, "emails": 0},
        "results": [],
        "active_campaign_id": None,
        "enrichment_df": None,
        "log_tick": 0,
        "auth_session": "",
        "auth_pin_sent": False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init_state()

# ======================== THREAD-SAFE БУФЕРИ ========================
_log_lock = threading.Lock()
_log_buffer = deque(maxlen=500)
_stat_lock = threading.Lock()
_stat_buffer = {"total": 0, "diamonds": 0, "whales": 0, "emails": 0}
_results_lock = threading.Lock()
_results_buffer = []

def _buf_log(msg: str, level: str = "info"):
    COLORS = {
        "info": "#60a5fa", "success": "#34d399", "error": "#f87171",
        "warn": "#fbbf24", "diamond": "#e879f9", "whale": "#4ade80",
        "skip": "#4b5563", "system": "#94a3b8"
    }
    color = COLORS.get(level, "#e2e8f0")
    t = time.strftime("%H:%M:%S")
    entry = (
        f'<span style="color:#475569;font-size:10px">[{t}]</span> '
        f'<span style="color:{color}">{msg}</span>'
    )
    with _log_lock:
        _log_buffer.appendleft(entry)

def _inc_stat(key: str):
    with _stat_lock:
        _stat_buffer[key] = _stat_buffer.get(key, 0) + 1

def _sync_to_session():
    with _log_lock:
        st.session_state.logs = list(_log_buffer)
    with _stat_lock:
        st.session_state.stats = dict(_stat_buffer)
    with _results_lock:
        st.session_state.results = list(_results_buffer)
    st.session_state.log_tick = st.session_state.get("log_tick", 0) + 1

def _reset_buffers():
    with _log_lock:
        _log_buffer.clear()
    with _stat_lock:
        for k in _stat_buffer:
            _stat_buffer[k] = 0
    with _results_lock:
        _results_buffer.clear()

# ======================== БАЗА ДАНИХ ========================
def init_db():
    with sqlite3.connect(DB_PATH, timeout=30) as conn:
        c = conn.cursor()
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.execute("""
            CREATE TABLE IF NOT EXISTS leads (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                domain          TEXT UNIQUE,
                company         TEXT,
                person          TEXT,
                role            TEXT,
                email           TEXT,
                email_status    TEXT,
                linkedin        TEXT,
                phone           TEXT,
                score           INTEGER,
                tier            TEXT,
                tech_stack      TEXT,
                employees       TEXT,
                revenue_sig     TEXT,
                country         TEXT,
                industry        TEXT,
                url             TEXT,
                funding         TEXT,
                key_customers   TEXT,
                competitors     TEXT,
                intent_hiring   TEXT,
                social_proof    TEXT,
                ready_email     TEXT,
                email_sequence  TEXT,
                icebreaker      TEXT,
                pain_points     TEXT,
                tech_gap        TEXT,
                dmu_champion    TEXT,
                dmu_economic    TEXT,
                dmu_gatekeeper  TEXT,
                campaign_id     INTEGER,
                ts              DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS campaigns (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                name            TEXT,
                theme_query     TEXT,
                target_leads    INTEGER DEFAULT 10,
                collected_leads INTEGER DEFAULT 0,
                status          TEXT DEFAULT 'pending',
                client_id       TEXT,
                created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
                completed_at    DATETIME
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS queue (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id     INTEGER UNIQUE,
                status          TEXT DEFAULT 'waiting',
                started_at      DATETIME,
                FOREIGN KEY(campaign_id) REFERENCES campaigns(id)
            )
        """)
        # Таблиця логів входу (аудит)
        c.execute("""
            CREATE TABLE IF NOT EXISTS access_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT,
                event       TEXT,
                details     TEXT,
                ts          DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("PRAGMA table_info(campaigns)")
        existing = [col[1] for col in c.fetchall()]
        if 'client_id' not in existing:
            c.execute("ALTER TABLE campaigns ADD COLUMN client_id TEXT")
        leads_cols = [col[1] for col in c.execute("PRAGMA table_info(leads)")]
        if 'campaign_id' not in leads_cols:
            c.execute("ALTER TABLE leads ADD COLUMN campaign_id INTEGER")
        conn.commit()

init_db()

def log_access(ip: str, event: str, details: str = ""):
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            conn.execute(
                "INSERT INTO access_log (ip, event, details) VALUES (?,?,?)",
                (ip, event, details[:500])
            )
            conn.commit()
    except Exception:
        pass

def _to_str(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, (list, tuple, dict)):
        return json.dumps(val, ensure_ascii=False)
    return str(val)

def db_save_lead(row: dict):
    try:
        with sqlite3.connect(DB_PATH, timeout=20) as c:
            values = (
                _to_str(row.get("domain", "")),
                _to_str(row.get("company", "")),
                _to_str(row.get("person", "")),
                _to_str(row.get("role", "")),
                _to_str(row.get("email", "")),
                _to_str(row.get("email_status", "")),
                _to_str(row.get("linkedin", "")),
                _to_str(row.get("phone", "")),
                int(row.get("score", 0)),
                _to_str(row.get("tier", "")),
                _to_str(row.get("tech_stack", "")),
                _to_str(row.get("employees", "")),
                _to_str(row.get("revenue_sig", "")),
                _to_str(row.get("country", "")),
                _to_str(row.get("industry", "")),
                _to_str(row.get("url", "")),
                _to_str(row.get("funding", "")),
                _to_str(row.get("key_customers", "")),
                _to_str(row.get("competitors", "")),
                _to_str(row.get("intent_hiring", "{}")),
                _to_str(row.get("social_proof", "")),
                _to_str(row.get("ready_email", "")),
                _to_str(row.get("email_sequence", "")),
                _to_str(row.get("icebreaker", "")),
                _to_str(row.get("pain_points", "")),
                _to_str(row.get("tech_gap", "")),
                _to_str(row.get("dmu_champion", "")),
                _to_str(row.get("dmu_economic", "")),
                _to_str(row.get("dmu_gatekeeper", "")),
                row.get("campaign_id"),
            )
            c.execute("""
                INSERT OR REPLACE INTO leads (
                    domain, company, person, role, email, email_status, linkedin,
                    phone, score, tier, tech_stack, employees, revenue_sig, country,
                    industry, url, funding, key_customers, competitors, intent_hiring,
                    social_proof, ready_email, email_sequence, icebreaker, pain_points,
                    tech_gap, dmu_champion, dmu_economic, dmu_gatekeeper, campaign_id
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, values)
            c.commit()
    except Exception as e:
        _buf_log(f"DB error: {e}", "error")

# ======================== КАМПАНІЇ ========================
def create_campaign(name: str, theme_query: str, target_leads: int, client_id: str) -> int:
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO campaigns (name, theme_query, target_leads, client_id, status)
            VALUES (?, ?, ?, ?, 'pending')
        """, (name, theme_query, target_leads, client_id))
        campaign_id = c.lastrowid
        conn.commit()
        return campaign_id

def add_to_queue(campaign_id: int):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO queue (campaign_id, status) VALUES (?, 'waiting')", (campaign_id,))
        conn.commit()

def get_next_campaign_from_queue() -> Optional[Dict]:
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
            SELECT c.id, c.name, c.theme_query, c.target_leads, c.collected_leads, c.client_id
            FROM campaigns c
            JOIN queue q ON c.id = q.campaign_id
            WHERE q.status = 'waiting' AND c.status = 'pending'
            ORDER BY c.created_at ASC LIMIT 1
        """)
        row = c.fetchone()
        if row:
            return {"id": row[0], "name": row[1], "theme_query": row[2],
                    "target_leads": row[3], "collected_leads": row[4], "client_id": row[5]}
        return None

def update_campaign_collected(campaign_id: int, new_collected: int):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("UPDATE campaigns SET collected_leads = ? WHERE id = ?", (new_collected, campaign_id))
        conn.commit()

def complete_campaign(campaign_id: int, client_id: str, leads_df: pd.DataFrame):
    webhook_url = f"{BASE_WEBHOOK_URL}/{client_id}"
    try:
        csv_data = leads_df.to_csv(index=False).encode("utf-8")
        files = {"file": ("leads.csv", csv_data, "text/csv")}
        headers = {"Authorization": f"Bearer {GLOBAL_API_KEY}"} if GLOBAL_API_KEY else {}
        response = requests.post(webhook_url, files=files, headers=headers, timeout=30)
        if response.status_code == 200:
            _buf_log(f"✅ Campaign {campaign_id}: leads sent to {webhook_url}", "success")
        else:
            _buf_log(f"⚠️ Campaign {campaign_id}: webhook returned {response.status_code}", "warn")
    except Exception as e:
        _buf_log(f"❌ Campaign {campaign_id}: webhook error {e}", "error")
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("UPDATE campaigns SET status='completed', completed_at=? WHERE id=?",
                  (datetime.now(), campaign_id))
        c.execute("DELETE FROM queue WHERE campaign_id=?", (campaign_id,))
        conn.commit()

def get_campaign_leads(campaign_id: int) -> pd.DataFrame:
    with sqlite3.connect(DB_PATH) as conn:
        return pd.read_sql_query("SELECT * FROM leads WHERE campaign_id=?", conn, params=(campaign_id,))

def get_all_campaigns() -> pd.DataFrame:
    with sqlite3.connect(DB_PATH) as conn:
        return pd.read_sql_query("SELECT * FROM campaigns ORDER BY created_at DESC", conn)

# ======================== DEEPSEEK API ========================
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10),
       retry=retry_if_exception_type(Exception), reraise=True)
def deepseek_call(prompt: str, system: str, api_key: str,
                  json_mode: bool = True, max_tokens: int = 3500) -> Optional[Any]:
    try:
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        payload = {
            "model": "deepseek-chat",
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": 0.2,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        response = requests.post(
            "https://api.deepseek.com/v1/chat/completions",
            headers=headers, json=payload, timeout=60
        )
        response.raise_for_status()
        raw = response.json()["choices"][0]["message"]["content"].strip()
        if not json_mode:
            return raw
        raw = re.sub(r"```(?:json)?|```", "", raw).strip()
        m = re.search(r"(\{.*\}|\[.*\])", raw, re.DOTALL)
        if m:
            return json.loads(m.group(1))
        return json.loads(raw)
    except Exception as e:
        _buf_log(f"DeepSeek API error: {e}", "error")
        raise

# ======================== ELITE PROMPT ========================
ELITE_SYSTEM = """You are a senior M&A analyst. Extract the following from the website content. Return JSON.

REQUIRED FIELDS:
- company_name: string
- employees: number (best guess)
- revenue_range: "10M-50M", "50M-200M", "200M-1B", "1B+"
- funding: string
- key_customers: list of 3-5 well-known brands
- competitors: list of 3 main competitors
- direct_phone: phone number found
- tech_stack: list of technologies
- headquarters: city, country
- industry: specific niche
- growth_signals: list
- recent_news: one positive recent event
- icebreaker: one specific detail to start conversation
- pain_points: list of three likely challenges
- tech_gap: what technology they might be missing
- ready_email: short sales email (3 sentences)
- score: 0-100

Return ONLY valid JSON."""

def ai_qualify_elite(text: str, domain: str, api_key: str) -> dict:
    fallback = {
        "company_name": domain, "employees": "unknown", "revenue_range": "",
        "funding": "", "key_customers": [], "competitors": [], "direct_phone": "",
        "tech_stack": [], "headquarters": "", "industry": "", "growth_signals": [],
        "recent_news": "", "icebreaker": "", "pain_points": [], "tech_gap": "",
        "ready_email": "", "score": 0
    }
    if len(text) < 150:
        return fallback
    clean_text = re.sub(r'<[^>]+>', ' ', text)
    clean_text = re.sub(r'\s+', ' ', clean_text).strip()[:6000]
    prompt = f"Domain: {domain}\nWebsite content:\n{clean_text}"
    result = deepseek_call(prompt, ELITE_SYSTEM, api_key, json_mode=True, max_tokens=3500)
    if isinstance(result, dict):
        for key in ["key_customers", "competitors", "tech_stack", "growth_signals", "pain_points"]:
            if key in result and isinstance(result[key], list):
                result[key] = ", ".join(str(v) for v in result[key])
            elif key in result and result[key] is None:
                result[key] = ""
        return {**fallback, **result}
    return fallback

# ======================== ДОРКИ ========================
HIGH_VALUE_NICHES = {
    "fintech": "enterprise fintech infrastructure banking API payment gateway",
    "logistics": "global logistics headquarters multimodal transport corporation supply chain",
    "cybersecurity": "enterprise cybersecurity data protection corporate security",
    "manufacturing": "industrial manufacturing equipment engineering plant automation",
    "ai_saas": "enterprise AI platform business automation SaaS solution"
}
COUNTRY_TLD = {
    "Germany": "site:.de", "USA": "site:.com", "UK": "site:.co.uk",
    "Singapore": "site:.sg", "France": "site:.fr", "Canada": "site:.ca",
    "Australia": "site:.com.au"
}
_BASE_DORKS = [
    'intitle:"enterprise" "clients include" "revenue" -blog -forum',
    'inurl:"customers" "case study" "global" "headquarters"',
    '"{q}" "annual revenue" "million" "employees" "headquarters"',
    '"{q}" "funding" "series" "venture capital" -crunchbase',
    '"{q}" "powered by" "enterprise" "cloud"',
    '"{q}" "partners" "Microsoft" "AWS" "Salesforce"',
    '"{q}" "careers" "head of" "director" "open roles"',
    '"{q}" "office" "Singapore" "London" "New York" "Tokyo"'
]

def generate_ultra_dorks(query: str, api_key: str, target_countries: List[str]) -> List[str]:
    niche = None
    for key, terms in HIGH_VALUE_NICHES.items():
        if key.lower() in query.lower() or any(t in query.lower() for t in terms.split()):
            niche = key
            break
    if not niche:
        niche = "manufacturing"
    enriched_query = HIGH_VALUE_NICHES.get(niche, query)
    tlds = [COUNTRY_TLD[c] for c in target_countries if c in COUNTRY_TLD]
    country_filters = " OR ".join(tlds) if tlds else ""
    prompt = f"""Target industry: {enriched_query}
Generate 30 Google dork queries.
Requirements:
- Exclude directories, blogs, forums, LinkedIn, Crunchbase.
- Use enterprise keywords: "enterprise", "solutions", "global", "headquarters".
- Include revenue signals: "annual revenue", "million".
- Country filters: {country_filters}
Return JSON: {{"queries": [...]}}"""
    result = deepseek_call(prompt, "Return only valid JSON.", api_key)
    ai_dorks = result.get("queries", []) if isinstance(result, dict) else []
    base = [d.format(q=enriched_query) for d in _BASE_DORKS]
    country_dorks = [
        f'{tld} "{enriched_query}" "CEO" "contact"'
        for c, tld in COUNTRY_TLD.items() if c in target_countries
    ]
    combined = ai_dorks + base + country_dorks
    seen, out = set(), []
    for d in combined:
        k = d.lower().strip()
        if k not in seen:
            seen.add(k)
            out.append(d)
    return out[:40]

# ======================== BLOCK LISTS ========================
_BLOCK_DOMAINS = {
    "linkedin.com", "facebook.com", "twitter.com", "x.com", "instagram.com", "youtube.com",
    "wikipedia.org", "crunchbase.com", "indeed.com", "glassdoor.com", "reddit.com", "quora.com",
    "dnb.com", "zoominfo.com", "apollo.io", "lusha.com", "yellowpages.com", "whitepages.com",
    "amazon.com", "ebay.com", "yelp.com", "tripadvisor.com",
    "g2.com", "capterra.com", "trustpilot.com", "clutch.co", "goodfirms.co",
    "techcrunch.com", "forbes.com", "bloomberg.com", "reuters.com", "wsj.com", "ft.com",
    "prnewswire.com", "businesswire.com", "globenewswire.com", "accesswire.com",
    "einpresswire.com", "prlog.org", "prweb.com",
    "marketresearch.com", "grandviewresearch.com", "mordorintelligence.com",
    "marketsandmarkets.com", "alliedmarketresearch.com", "statista.com",
    "businessresearchinsights.com", "verifiedmarketresearch.com",
    "intellectualmarketinsights.com", "marketreportanalytics.com",
    "researchandmarkets.com", "reportlinker.com",
    "databridgemarketresearch.com", "fortunebusinessinsights.com",
    "marketwatch.com", "seekingalpha.com", "businessinsider.com",
    "siliconangle.com", "venturebeat.com", "zdnet.com", "cnet.com",
    "wired.com", "theverge.com", "engadget.com", "gizmodo.com",
    "plasticsnews.com", "rubbernews.com", "chemicalweek.com", "icis.com",
    "industrydive.com", "supplychain247.com", "logisticsmgmt.com",
    "q4cdn.com", "ir.net", "prnews.io", "sec.gov",
    "medium.com", "substack.com", "wordpress.com", "blogger.com",
    "jobs.lever.co", "greenhouse.io", "workday.com", "bamboohr.com",
}
_BLOCK_EXTENSIONS = (
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".rar", ".tar", ".gz", ".mp4", ".mp3", ".avi",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".xml", ".json", ".csv",
)
_BLOCK_TLDS = (".gov", ".edu", ".ac.uk", ".mil")
_BLOCK_URL_PATTERNS = (
    "/sites/default/files/", "/wp-content/uploads/", "/content/uploads/",
    "/doc_financials/", "/files/doc_", "/system/files/",
    "/news-releases/news-release-details/",
    "/investor-relations/press-releases/",
    "q4cdn.com", "ir.net/",
)

def _is_blocked_domain(domain: str) -> bool:
    for b in _BLOCK_DOMAINS:
        if b in domain:
            return True
    for t in _BLOCK_TLDS:
        if domain.endswith(t):
            return True
    return False

def _is_blocked_url(url: str) -> bool:
    url_lower = url.lower()
    parsed_path = urlparse(url).path.lower()
    for ext in _BLOCK_EXTENSIONS:
        if parsed_path.endswith(ext):
            return True
    for pattern in _BLOCK_URL_PATTERNS:
        if pattern in url_lower:
            return True
    return False

def serper_validate_key(key: str) -> Tuple[bool, str]:
    if not key or len(key) < 10:
        return False, "Ключ порожній або занадто короткий"
    try:
        r = requests.post(
            "https://google.serper.dev/search",
            headers={"X-API-KEY": key, "Content-Type": "application/json"},
            json={"q": "test", "num": 1}, timeout=15
        )
        if r.status_code == 200:
            return True, "OK"
        return False, f"HTTP {r.status_code}"
    except Exception as e:
        return False, str(e)[:120]

def _serper_one(query: str, key: str, num: int = 10) -> list:
    try:
        r = requests.post(
            "https://google.serper.dev/search",
            headers={"X-API-KEY": key, "Content-Type": "application/json"},
            json={"q": query, "num": num, "gl": "com"}, timeout=30
        )
        if r.status_code == 200:
            return r.json().get("organic", [])
        elif r.status_code == 429:
            _buf_log("⚠️ Serper 429 – пауза 10 сек", "warn")
            time.sleep(10)
            r2 = requests.post(
                "https://google.serper.dev/search",
                headers={"X-API-KEY": key, "Content-Type": "application/json"},
                json={"q": query, "num": num, "gl": "com"}, timeout=30
            )
            return r2.json().get("organic", []) if r2.status_code == 200 else []
        elif r.status_code == 400:
            _buf_log("⚠️ Serper 400 – query not allowed", "warn")
            return []
        else:
            _buf_log(f"⚠️ Serper HTTP {r.status_code}", "warn")
            return []
    except Exception as e:
        _buf_log(f"⚠️ Serper error: {str(e)[:100]}", "warn")
        return []

def collect_urls(dorks: list, serper_key: str, max_total: int) -> list:
    seen_domains = set()
    results = []
    consecutive_empty = 0
    for i, q in enumerate(dorks):
        if len(results) >= max_total:
            break
        items = _serper_one(q, serper_key, num=10)
        if not items:
            consecutive_empty += 1
            if consecutive_empty >= 5:
                _buf_log("🛑 5 порожніх відповідей підряд – зупиняю пошук", "error")
                break
        else:
            consecutive_empty = 0
        added = 0
        for item in items:
            if len(results) >= max_total:
                break
            link = item.get("link", "")
            if not link:
                continue
            domain = urlparse(link).netloc.replace("www.", "").lower().strip("/")
            if not domain or len(domain) < 6:
                continue
            if _is_blocked_domain(domain) or domain in seen_domains:
                continue
            if _is_blocked_url(link):
                _buf_log(f"⛔ Пропускаємо файл/IR: {link[:70]}...", "skip")
                continue
            seen_domains.add(domain)
            results.append({
                "url": link, "domain": domain,
                "title": item.get("title", ""),
                "snippet": item.get("snippet", "")
            })
            added += 1
        _buf_log(
            f"🔎 [{i+1}/{len(dorks)}] +{added} сайтів → всього {len(results)}/{max_total}",
            "system" if added > 0 else "skip"
        )
        time.sleep(0.5)
    return results[:max_total]

# ======================== SCRAPING ========================
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_CONTACT_PATHS = [
    "/contact", "/contact-us", "/contacts", "/get-in-touch",
    "/about", "/about-us", "/team", "/our-team",
    "/impressum", "/imprint", "/kontakt", "/company"
]
_EMAIL_SKIP = {
    "sentry.io", "amazonaws.com", "cloudflare.com", "google.com",
    "w3.org", "schema.org", "example.com", "yourdomain.com",
    "email.com", "domain.com", "test.com"
}

def _clean_emails(raw: list) -> list:
    out = []
    for e in set(raw):
        e = e.strip().lower()
        dom = e.split("@")[-1]
        if dom in _EMAIL_SKIP or "." not in dom:
            continue
        if any(x in e for x in ("noreply", "no-reply", "donotreply",
                                  "abuse@", "postmaster@", "webmaster@",
                                  "example", "test@")):
            continue
        out.append(e)
    return out

async def _human_like_delay():
    await asyncio.sleep(random.uniform(0.3, 1.2))

async def _page_get(page, url: str, timeout: int = 20000):
    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=timeout)
        await page.wait_for_selector('body', timeout=5000)
        await page.wait_for_load_state("networkidle", timeout=5000)
        await _human_like_delay()
        await page.mouse.move(random.randint(100, 500), random.randint(100, 500))
        await page.evaluate("window.scrollBy(0, window.innerHeight * 0.5)")
        await _human_like_delay()
        text = await page.evaluate("document.body ? document.body.innerText : ''") or ""
        html = await page.content() or ""
        mailto = re.findall(
            r"mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})", html, re.I
        )
        plain = _EMAIL_RE.findall(text)
        return text, list(set(mailto + plain))
    except Exception as e:
        _buf_log(f"⚠️ Page load error {url}: {str(e)[:80]}", "warn")
        return "", []

async def deep_scrape(base_url: str, browser, depth: int, proxy: Optional[str] = None):
    ctx_options = {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "viewport": {"width": 1280, "height": 800},
        "ignore_https_errors": True,
    }
    if proxy:
        ctx_options["proxy"] = {"server": proxy}
    ctx = await browser.new_context(**ctx_options)
    page = await ctx.new_page()
    await page.route(
        "**/*.{png,jpg,jpeg,gif,webp,svg,woff,woff2,ttf,eot,mp4,mp3,pdf}",
        lambda r: r.abort()
    )
    all_text, all_emails = "", []
    try:
        text, emails = await _page_get(page, base_url)
        all_text += text[:depth]
        all_emails += emails
        if not _clean_emails(all_emails) or len(all_text) < 500:
            parsed = urlparse(base_url)
            base_origin = f"{parsed.scheme}://{parsed.netloc}"
            for path in _CONTACT_PATHS[:8]:
                try:
                    t, e = await _page_get(page, base_origin + path, timeout=12000)
                    all_text += " " + t[:2000]
                    all_emails += e
                    if _clean_emails(e):
                        break
                except Exception:
                    pass
    except Exception as e:
        _buf_log(f"Scrape error {base_url}: {e}", "error")
    finally:
        await ctx.close()
    return {"text": all_text[:depth * 2], "emails": _clean_emails(all_emails)}

# ======================== INTENT / SOCIAL / DMU ========================
async def get_intent_hiring(company: str, domain: str, serper_key: str) -> Dict:
    hiring = {"roles": [], "platforms": []}
    queries = [
        f'site:greenhouse.io "{company}" OR "{domain}"',
        f'site:lever.co "{company}" OR "{domain}"',
        f'site:workable.com "{company}" OR "{domain}"'
    ]
    for q in queries:
        items = _serper_one(q, serper_key, num=5)
        for item in items:
            title = item.get("title", "")
            hiring["platforms"].append(q.split("site:")[1].split()[0])
            roles = re.findall(
                r"(Head of|Director|VP|Manager|DevOps|Engineer|Sales|Marketing|Product|IT)",
                title, re.I
            )
            hiring["roles"].extend(roles)
        await asyncio.sleep(0.4)
    hiring["roles"] = list(set(hiring["roles"]))[:5]
    return hiring

async def get_social_proof(company: str, domain: str, serper_key: str) -> str:
    queries = [
        f'"{company}" news after:2025-01-01',
        f'"{domain}" award OR recognition OR "named" "leader"'
    ]
    for q in queries:
        items = _serper_one(q, serper_key, num=3)
        for item in items:
            title = item.get("title", "")
            link = item.get("link", "")
            if title and len(title) > 10:
                return f"{title} ({link})"
        await asyncio.sleep(0.5)
    return ""

async def find_dmu(company: str, domain: str, serper_key: str) -> Dict[str, str]:
    dmu = {"champion": "", "economic": "", "gatekeeper": ""}
    for role in ["Head of Product", "Product Manager", "Operations Manager"]:
        items = _serper_one(f'site:linkedin.com/in/ "{role}" "{company}"', serper_key, num=2)
        if items and items[0].get("link"):
            dmu["champion"] = items[0]["link"]
            break
        await asyncio.sleep(0.3)
    for role in ["CEO", "CFO", "VP of Finance", "Managing Director"]:
        items = _serper_one(f'site:linkedin.com/in/ "{role}" "{company}"', serper_key, num=2)
        if items and items[0].get("link"):
            dmu["economic"] = items[0]["link"]
            break
        await asyncio.sleep(0.3)
    for role in ["CTO", "Head of IT", "VP of Engineering", "IT Director"]:
        items = _serper_one(f'site:linkedin.com/in/ "{role}" "{company}"', serper_key, num=2)
        if items and items[0].get("link"):
            dmu["gatekeeper"] = items[0]["link"]
            break
        await asyncio.sleep(0.3)
    return dmu

# ======================== LINKEDIN ========================
def osint_linkedin_smart(company: str, domain: str, target_role: str,
                          serper_key: str, deepseek_key: str, best_contact_role: str) -> Dict:
    base_name = domain.split(".")[0].replace("-", " ").title()
    roles_to_search = [
        target_role, "CEO OR Founder OR Managing Director",
        "CMO OR Chief Marketing Officer", "CTO OR Chief Technology Officer",
        "Sales Director OR Head of Sales", "VP of Sales"
    ]
    seen_links, contacts = set(), []
    for role in roles_to_search:
        if len(contacts) >= 10:
            break
        items = _serper_one(
            f'site:linkedin.com/in/ "{role}" "{company or base_name}"',
            serper_key, num=5
        )
        for item in items:
            title = item.get("title", "")
            link = item.get("link", "")
            if link in seen_links:
                continue
            name_raw = re.split(r"\s[-–|]\s", title)[0].strip()
            words = name_raw.split()
            if not (2 <= len(words) <= 4 and
                    not re.search(r"\d|@|http", name_raw) and
                    4 <= len(name_raw) <= 40):
                continue
            role_extracted = title.replace(name_raw, "").strip(" -–|").strip() or role
            seen_links.add(link)
            contacts.append({"name": name_raw, "linkedin": link, "role": role_extracted})
        time.sleep(0.3)
    if not contacts:
        return {"primary": {"name": "N/A", "linkedin": "N/A", "role": "N/A"}, "all": []}
    system = ('You are a sales assistant. Choose the best contact for selling B2B enterprise solutions. '
              'Return JSON: {"selected_index": 0}')
    contacts_str = "\n".join([f"{i}: {c['name']} - {c['role']}" for i, c in enumerate(contacts)])
    result = deepseek_call(
        f"Target role preference: {best_contact_role}\nContacts:\n{contacts_str}",
        system, deepseek_key, json_mode=True, max_tokens=200
    )
    if isinstance(result, dict) and "selected_index" in result:
        idx = result["selected_index"]
        primary = contacts[idx] if 0 <= idx < len(contacts) else contacts[0]
    else:
        primary = contacts[0]
        for c in contacts:
            if best_contact_role.lower() in c["role"].lower() or "ceo" in c["role"].lower():
                primary = c
                break
    return {"primary": primary, "all": contacts}

# ======================== EMAIL VERIFICATION ========================
def verify_email_millionverifier(email: str, api_key: str) -> str:
    if not api_key or not email or email == "N/A":
        return "SKIPPED"
    try:
        r = requests.get(
            "https://api.millionverifier.com/api/v3/",
            params={"api": api_key, "email": email, "timeout": 10},
            timeout=20
        )
        if r.status_code != 200:
            return "MV_ERROR"
        data = r.json()
        result = data.get("result", "unknown").lower()
        subresult = data.get("subresult", "").lower()
        if result == "ok":
            return "MV_VALID" if subresult == "valid" else "MV_CATCH_ALL" if subresult == "catch_all" else "MV_OK"
        elif result == "error":
            return "MV_DISPOSABLE" if "disposable" in subresult else "MV_INVALID"
        return "MV_UNKNOWN"
    except requests.exceptions.Timeout:
        return "MV_TIMEOUT"
    except Exception as e:
        _buf_log(f"⚠️ MV error {email}: {str(e)[:80]}", "warn")
        return "MV_ERROR"

def is_email_deliverable(status: str) -> bool:
    return status in ("VALID", "RISKY", "MV_VALID", "MV_CATCH_ALL", "MV_OK",
                      "PROSPEO", "HUNTER", "ACCEPT_ALL")

# ======================== EMAIL DISCOVERY ========================
def _email_patterns(first: str, last: str, domain: str) -> list:
    f, l = first.lower().strip(), last.lower().strip()
    if not f or not l:
        return [f"contact@{domain}", f"info@{domain}"]
    return [
        f"{f}.{l}@{domain}", f"{f}{l}@{domain}", f"{f[0]}{l}@{domain}",
        f"{f}.{l[0]}@{domain}", f"{f[0]}.{l}@{domain}", f"{f}@{domain}",
        f"contact@{domain}", f"info@{domain}"
    ]

def _get_mx(domain: str) -> Optional[str]:
    try:
        records = dns.resolver.resolve(domain, "MX")
        best = sorted(records, key=lambda r: r.preference)[0]
        return str(best.exchange).rstrip(".")
    except Exception:
        return None

_BIG_MAIL = ["google.com", "outlook.com", "microsoft.com", "yahoo.com",
             "protection.outlook.com", "amazonses.com"]

def smtp_verify(email: str) -> str:
    domain = email.split("@")[-1]
    mx = _get_mx(domain)
    if not mx:
        return "INVALID"
    if any(b in mx for b in _BIG_MAIL):
        return "RISKY"
    try:
        with smtplib.SMTP(timeout=8) as s:
            s.connect(mx, 25)
            s.helo("verify.titan.io")
            s.mail("check@titan.io")
            code, _ = s.rcpt(email)
            return "VALID" if code == 250 else "INVALID"
    except Exception:
        return "UNVERIFIABLE"

def find_email_prospeo(first: str, last: str, domain: str, key: str) -> Optional[str]:
    if not key or first == "N/A":
        return None
    try:
        r = requests.post(
            "https://api.prospeo.io/email-finder",
            headers={"X-KEY": key},
            json={"first_name": first, "last_name": last, "domain": domain},
            timeout=15
        )
        if r.status_code == 200:
            res = r.json().get("response", {})
            if res.get("email_status") in ("VALID", "ACCEPT_ALL"):
                return res.get("email")
    except Exception:
        pass
    return None

def find_email_hunter(first: str, last: str, domain: str, key: str) -> Optional[str]:
    if not key or first == "N/A":
        return None
    try:
        r = requests.get(
            "https://api.hunter.io/v2/email-finder",
            params={"domain": domain, "first_name": first, "last_name": last, "api_key": key},
            timeout=15
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            if d.get("email") and int(d.get("confidence", 0)) > 50:
                return d["email"]
    except Exception:
        pass
    return None

def find_email_bruteforce(first: str, last: str, domain: str) -> tuple:
    if not _get_mx(domain):
        return None, "INVALID"
    for em in _email_patterns(first, last, domain):
        status = smtp_verify(em)
        if status in ("VALID", "RISKY"):
            return em, status
    return None, "NOT_FOUND"

# ======================== CORE WORKER ========================
async def process_one(target: dict, sem: asyncio.Semaphore, cfg: dict, browser):
    domain = target["domain"]
    url = target["url"]
    campaign_id = cfg.get("campaign_id")
    async with sem:
        try:
            if _is_blocked_url(url) or _is_blocked_domain(domain):
                _buf_log(f"⛔ Пропускаємо {domain}", "skip")
                return
            _buf_log(f"🔄 ОБРОБКА {domain} (campaign {campaign_id})", "system")
            data = await deep_scrape(url, browser, cfg["scrape_depth"], proxy=cfg.get("proxy"))
            text, emails = data["text"], data["emails"]

            qual = await asyncio.to_thread(ai_qualify_elite, text, domain, cfg["deepseek_key"])
            score = int(qual.get("score", 0))
            if cfg["only_whales"] and score < cfg["min_score"]:
                _buf_log(f"⏭ {domain} score={score} — below threshold", "skip")
                return

            company     = qual.get("company_name", domain)
            revenue_range = qual.get("revenue_range", "")
            headquarters  = qual.get("headquarters", "")
            icebreaker    = qual.get("icebreaker", "")
            pain_points   = qual.get("pain_points", "")
            ready_email   = qual.get("ready_email", "")
            tech_gap      = qual.get("tech_gap", "")

            email_sequence = ready_email or (
                f"Email 1: {icebreaker}\nEmail 2: {pain_points}\nEmail 3: Let's schedule a call."
            )

            intent       = await get_intent_hiring(company, domain, cfg["serper_key"])
            social_proof = await get_social_proof(company, domain, cfg["serper_key"])
            dmu          = await find_dmu(company, domain, cfg["serper_key"])
            li_data      = await asyncio.to_thread(
                osint_linkedin_smart, company, domain, cfg["target_role"],
                cfg["serper_key"], cfg["deepseek_key"], cfg.get("best_contact_role", "CEO")
            )
            primary    = li_data["primary"]
            person     = primary["name"]
            linkedin   = primary["linkedin"]
            role_found = primary["role"] if primary["role"] != "N/A" else cfg["target_role"]

            email, email_status = "N/A", "UNKNOWN"
            parts = person.split() if person != "N/A" else []
            first = parts[0] if parts else "N/A"
            last  = parts[-1] if len(parts) >= 2 else "N/A"

            if emails:
                email = emails[0]
                email_status = await asyncio.to_thread(smtp_verify, email)
            if email == "N/A":
                found = await asyncio.to_thread(find_email_prospeo, first, last, domain, cfg["prospeo_key"])
                if found:
                    email, email_status = found, "PROSPEO"
            if email == "N/A":
                found = await asyncio.to_thread(find_email_hunter, first, last, domain, cfg["hunter_key"])
                if found:
                    email, email_status = found, "HUNTER"
            if email == "N/A" and cfg.get("bruteforce"):
                found, st_val = await asyncio.to_thread(find_email_bruteforce, first, last, domain)
                if found:
                    email, email_status = found, st_val
            if email != "N/A" and cfg.get("millionverifier_key"):
                mv = await asyncio.to_thread(verify_email_millionverifier, email, cfg["millionverifier_key"])
                _buf_log(f"📧 MV [{email}]: {mv}", "info")
                if mv in ("MV_INVALID", "MV_DISPOSABLE"):
                    _buf_log(f"🚫 MV відхилив {email} ({mv})", "warn")
                    email, email_status = "N/A", mv
                else:
                    email_status = mv

            country = ""
            if headquarters:
                hq_parts = headquarters.split(",")
                if len(hq_parts) > 1:
                    country = hq_parts[-1].strip()
            tier = "💎 DIAMOND" if score >= 80 else "🐋 WHALE"

            row = {
                "domain": domain, "company": company, "person": person, "role": role_found,
                "email": email, "email_status": email_status, "linkedin": linkedin,
                "phone": qual.get("direct_phone", ""), "score": score, "tier": tier,
                "tech_stack": qual.get("tech_stack", ""), "employees": qual.get("employees", "unknown"),
                "revenue_sig": revenue_range, "country": country,
                "industry": qual.get("industry", ""), "url": url,
                "source_query": cfg.get("query", ""),
                "funding": qual.get("funding", ""),
                "key_customers": qual.get("key_customers", ""),
                "competitors": qual.get("competitors", ""),
                "intent_hiring": json.dumps(intent), "social_proof": social_proof,
                "ready_email": ready_email, "email_sequence": email_sequence,
                "icebreaker": icebreaker, "pain_points": pain_points, "tech_gap": tech_gap,
                "dmu_champion": dmu.get("champion", ""),
                "dmu_economic": dmu.get("economic", ""),
                "dmu_gatekeeper": dmu.get("gatekeeper", ""),
                "campaign_id": campaign_id,
            }
            db_save_lead(row)
            with _results_lock:
                _results_buffer.append(row)
            _inc_stat("total")
            if "💎" in tier:
                _inc_stat("diamonds")
            if "🐋" in tier:
                _inc_stat("whales")
            if email != "N/A":
                _inc_stat("emails")
            _buf_log(
                f"{tier} [{score}] {domain} | {person} | {email} [{email_status}] | 💰 {revenue_range}",
                "diamond" if "💎" in tier else "whale"
            )
        except Exception as e:
            _buf_log(f"❌ {domain}: {str(e)[:100]}", "error")

# ======================== CAMPAIGN RUNNER ========================
async def run_campaign(campaign: Dict, cfg: Dict):
    campaign_id = campaign["id"]
    target = campaign["target_leads"]
    _buf_log(f"🚀 Starting campaign '{campaign['name']}' target: {target}", "system")
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("UPDATE campaigns SET status='running' WHERE id=?", (campaign_id,))
        c.execute("UPDATE queue SET status='running', started_at=? WHERE campaign_id=?",
                  (datetime.now(), campaign_id))
        conn.commit()
    total_collected = campaign["collected_leads"]
    while total_collected < target:
        needed = target - total_collected
        _buf_log(f"📊 Campaign {campaign_id}: {total_collected}/{target}", "info")
        dorks = generate_ultra_dorks(campaign["theme_query"], cfg["deepseek_key"], cfg["target_countries"])
        if not dorks:
            break
        max_sites = min(500, needed * 5)
        targets = await asyncio.to_thread(collect_urls, dorks, cfg["serper_key"], max_sites)
        if not targets:
            break
        sem = asyncio.Semaphore(cfg["threads"])
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--disable-images"]
            )
            cfg["campaign_id"] = campaign_id
            await asyncio.gather(*[process_one(t, sem, cfg, browser) for t in targets])
            await browser.close()
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM leads WHERE campaign_id=?", (campaign_id,))
            total_collected = c.fetchone()[0]
        update_campaign_collected(campaign_id, total_collected)
        _buf_log(f"✅ Campaign {campaign_id}: total now {total_collected}/{target}", "success")
        if total_collected >= target:
            break
        await asyncio.sleep(5)
    if total_collected >= target:
        complete_campaign(campaign_id, campaign["client_id"], get_campaign_leads(campaign_id))
        _buf_log(f"🏁 Campaign '{campaign['name']}' completed!", "diamond")
    else:
        _buf_log(f"⚠️ Campaign ended with {total_collected}/{target}", "warn")
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("UPDATE campaigns SET status='failed' WHERE id=?", (campaign_id,))
            c.execute("DELETE FROM queue WHERE campaign_id=?", (campaign_id,))
            conn.commit()

# ======================== ENRICHMENT ========================
async def enrich_one_domain(domain: str, cfg: dict, browser) -> dict:
    url = f"https://{domain}" if not domain.startswith("http") else domain
    try:
        if _is_blocked_url(url):
            return {"domain": domain, "error": "blocked"}
        _buf_log(f"🔍 Enriching {domain}", "system")
        data = await deep_scrape(url, browser, cfg["scrape_depth"], proxy=cfg.get("proxy"))
        qual = await asyncio.to_thread(ai_qualify_elite, data["text"], domain, cfg["deepseek_key"])
        company = qual.get("company_name", domain)
        li_data = await asyncio.to_thread(
            osint_linkedin_smart, company, domain, cfg["target_role"],
            cfg["serper_key"], cfg["deepseek_key"], cfg.get("best_contact_role", "CEO")
        )
        primary    = li_data["primary"]
        person     = primary["name"]
        linkedin   = primary["linkedin"]
        role_found = primary["role"] if primary["role"] != "N/A" else cfg["target_role"]

        email, email_status = "N/A", "UNKNOWN"
        parts = person.split() if person != "N/A" else []
        first = parts[0] if parts else "N/A"
        last  = parts[-1] if len(parts) >= 2 else "N/A"

        if data["emails"]:
            email = data["emails"][0]
            email_status = await asyncio.to_thread(smtp_verify, email)
        if email == "N/A":
            found = await asyncio.to_thread(find_email_prospeo, first, last, domain, cfg["prospeo_key"])
            if found:
                email, email_status = found, "PROSPEO"
        if email == "N/A":
            found = await asyncio.to_thread(find_email_hunter, first, last, domain, cfg["hunter_key"])
            if found:
                email, email_status = found, "HUNTER"
        if email == "N/A" and cfg.get("bruteforce"):
            found, st_val = await asyncio.to_thread(find_email_bruteforce, first, last, domain)
            if found:
                email, email_status = found, st_val
        if email != "N/A" and cfg.get("millionverifier_key"):
            mv = await asyncio.to_thread(verify_email_millionverifier, email, cfg["millionverifier_key"])
            if mv in ("MV_INVALID", "MV_DISPOSABLE"):
                email, email_status = "N/A", mv
            else:
                email_status = mv

        headquarters = qual.get("headquarters", "")
        country = ""
        if headquarters:
            hq_parts = headquarters.split(",")
            if len(hq_parts) > 1:
                country = hq_parts[-1].strip()

        result = {
            "domain": domain, "company": company, "person": person, "role": role_found,
            "linkedin": linkedin, "email": email, "email_status": email_status,
            "phone": qual.get("direct_phone", ""),
            "icebreaker": qual.get("icebreaker", ""),
            "tech_gap": qual.get("tech_gap", ""),
            "pain_points": qual.get("pain_points", ""),
            "score": qual.get("score", 0),
            "revenue_range": qual.get("revenue_range", ""),
            "employees": qual.get("employees", ""),
            "industry": qual.get("industry", ""),
            "country": country,
        }
        _buf_log(f"✅ Enriched {domain}: {person} | {email} [{email_status}]", "success")
        return result
    except Exception as e:
        _buf_log(f"❌ Failed {domain}: {str(e)[:100]}", "error")
        return {"domain": domain, "error": str(e)}

# ════════════════════════════════════════════════
#  UI — STREAMLIT
# ════════════════════════════════════════════════
st.set_page_config(
    page_title="TITAN v5.0",
    layout="wide",
    page_icon="🔱"
)
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Orbitron:wght@400;700;900&display=swap');
* { margin:0; padding:0; box-sizing:border-box; }
html,body,.stApp { background:radial-gradient(circle at 10% 20%,#0a0f1e,#030712); color:#e2e8f0; font-family:'Inter',sans-serif; }
div[data-testid="stMetricValue"] { font-size:2.2rem; font-weight:700; background:linear-gradient(135deg,#c084fc,#60a5fa); -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text; }
div[data-testid="stMetricLabel"] { font-size:0.8rem; text-transform:uppercase; letter-spacing:2px; color:#94a3b8; }
[data-testid="stSidebar"] { background:rgba(5,10,20,0.8); backdrop-filter:blur(16px); border-right:1px solid #1e2d4d; }
.titan-title { font-family:'Orbitron',sans-serif; font-size:2.4rem; font-weight:900; background:linear-gradient(90deg,#e879f9,#60a5fa,#34d399); -webkit-background-clip:text; -webkit-text-fill-color:transparent; margin-bottom:0.5rem; }
.sec-hdr { font-family:'Orbitron',sans-serif; font-size:0.7rem; color:#38bdf8; letter-spacing:3px; text-transform:uppercase; border-bottom:1px solid #1e2d4d; margin:20px 0 14px; padding-bottom:6px; }
.log-container { background:#020509; border-radius:20px; border:1px solid #1e2d4d; padding:14px; height:420px; overflow-y:auto; font-family:'Share Tech Mono',monospace; font-size:11px; line-height:1.6; box-shadow:inset 0 0 10px rgba(0,0,0,0.5); }
.stButton > button { background:linear-gradient(90deg,#1e2d4d,#0f172a); border:1px solid #38bdf8; border-radius:40px; color:#e2e8f0; font-weight:600; transition:all 0.2s; }
.stButton > button:hover { background:linear-gradient(90deg,#2563eb,#1e40af); border-color:#60a5fa; color:white; transform:scale(1.01); }
.live-badge { display:inline-block; background:#34d399; color:#020509; font-size:9px; font-weight:700; letter-spacing:1.5px; padding:2px 8px; border-radius:20px; vertical-align:middle; margin-left:8px; animation:pulse 1.5s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
</style>
""", unsafe_allow_html=True)

# ════════ ПЕРЕВІРКА AUTH — ПЕРШИМ РЯДКОМ ════════
require_auth()
# ════════════════════════════════════════════════

st.markdown('<div class="titan-title">🔱 TITAN v5.0 — CAMPAIGN MANAGER + ENRICHMENT</div>',
            unsafe_allow_html=True)
st.caption("Secured Edition — Telegram PIN Auth enabled")

# ======================== SIDEBAR ========================
with st.sidebar:
    st.markdown("### 🔑 API KEYS")
    deepseek_key         = st.text_input("DeepSeek API Key ★", type="password")
    serper_key           = st.text_input("Serper API Key ★", type="password")
    prospeo_key          = st.text_input("Prospeo (optional)", type="password")
    hunter_key           = st.text_input("Hunter.io (optional)", type="password")

    st.markdown('<div class="sec-hdr">📧 EMAIL VERIFICATION</div>', unsafe_allow_html=True)
    use_millionverifier  = st.checkbox("Use MillionVerifier", value=True)
    millionverifier_key  = st.text_input("MillionVerifier API Key", type="password")
    if use_millionverifier and millionverifier_key:
        if st.button("🧪 Test MillionVerifier"):
            res = verify_email_millionverifier("test@gmail.com", millionverifier_key)
            st.success(f"MV: {res}") if "ERROR" not in res else st.error(f"MV: {res}")

    st.markdown('<div class="sec-hdr">🔐 СЕСІЯ</div>', unsafe_allow_html=True)
    ip_now = _get_client_ip()
    st.caption(f"IP: `{ip_now}`")
    with _AUTH_LOCK:
        sess_valid = check_session(st.session_state.get("auth_session",""), ip_now)
    st.success("✅ Авторизовано") if sess_valid else st.error("❌ Сесія прострочена")
    if st.button("🔒 Вийти"):
        with _AUTH_LOCK:
            _active_sessions.pop(st.session_state.get("auth_session",""), None)
        st.session_state.auth_session = ""
        st.session_state.auth_pin_sent = False
        st.rerun()

    # Адмін-панель: активні сесії та бани
    with st.expander("🛡️ Security Admin"):
        with _AUTH_LOCK:
            n_sess = len(_active_sessions)
            n_bans = len(_banned_ips)
        st.metric("Активних сесій", n_sess)
        st.metric("Заблокованих IP", n_bans)
        if n_bans > 0 and st.button("🔓 Розблокувати всі IP"):
            with _AUTH_LOCK:
                _banned_ips.clear()
                _fail_count.clear()
            st.success("Всі бани знято")
        try:
            with sqlite3.connect(DB_PATH) as conn:
                log_df = pd.read_sql_query(
                    "SELECT ip,event,ts FROM access_log ORDER BY ts DESC LIMIT 20", conn
                )
            if not log_df.empty:
                st.dataframe(log_df, use_container_width=True)
        except Exception:
            pass

    st.markdown('<div class="sec-hdr">⚙️ ENGINE</div>', unsafe_allow_html=True)
    parallel         = st.slider("Parallel workers", 1, 50, DEFAULT_PARALLEL)
    scrape_depth     = st.slider("Scrape depth (chars)", 2000, 10000, DEFAULT_SCRAPE_DEPTH, 500)
    min_score        = st.slider("Min score (0-100)", 0, 100, DEFAULT_MIN_SCORE)
    only_whales      = st.checkbox("Skip low-score leads", value=True)
    bruteforce       = st.checkbox("SMTP bruteforce (slow)", value=False)
    use_proxy        = st.checkbox("Use proxy", value=False)
    proxy_url        = st.text_input("Proxy URL") if use_proxy else ""
    target_countries = st.multiselect("Target countries", list(COUNTRY_TLD.keys()),
                                      default=["Germany", "USA", "UK", "Singapore"])
    target_role      = st.text_input("Target role", value="CEO OR Founder OR Managing Director")
    best_contact_role= st.text_input("Best contact role", value="CEO")

# ======================== МЕТРИКИ ========================
m1, m2, m3, m4 = st.columns(4)
m1.metric("🎯 Total",    st.session_state.stats.get("total", 0))
m2.metric("💎 Diamonds", st.session_state.stats.get("diamonds", 0))
m3.metric("🐋 Whales",   st.session_state.stats.get("whales", 0))
m4.metric("📧 Emails",   st.session_state.stats.get("emails", 0))

# ======================== LIVE LOG ========================
st.markdown('### 📡 Телеметрія <span class="live-badge">LIVE</span>', unsafe_allow_html=True)
log_placeholder = st.empty()

def _render_logs():
    html = "<br>".join(st.session_state.logs[:300]) if st.session_state.logs else \
        '<span style="color:#475569">Логи з\'являться після запуску...</span>'
    log_placeholder.markdown(f'<div class="log-container">{html}</div>', unsafe_allow_html=True)

_render_logs()

# ======================== TABS ========================
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📋 Campaigns", "➕ Create Campaign", "⏳ Queue & Run",
    "📊 Leads", "📈 Enrichment", "📧 Email Verifier"
])

with tab1:
    st.subheader("Existing Campaigns")
    df_camps = get_all_campaigns()
    if not df_camps.empty:
        st.dataframe(
            df_camps[["id","name","theme_query","target_leads","collected_leads",
                       "status","client_id","created_at"]],
            use_container_width=True
        )
    else:
        st.info("No campaigns yet.")

with tab2:
    st.subheader("Create New Campaign")
    with st.form("create_campaign_form"):
        name         = st.text_input("Campaign Name")
        theme_query  = st.text_area("Theme / Query", height=80)
        target_leads = st.number_input("Target leads", min_value=1, max_value=10000, value=50)
        client_id    = st.text_input("Client ID", placeholder="client_123")
        if st.form_submit_button("Create Campaign"):
            if not name or not theme_query or not client_id:
                st.error("Name, query and client ID are required")
            else:
                cid = create_campaign(name, theme_query, target_leads, client_id)
                log_access(_get_client_ip(), "create_campaign", f"id={cid} name={name}")
                st.success(f"Campaign created with ID {cid}")
                st.rerun()

with tab3:
    st.subheader("Queue Management")
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
            SELECT q.id, c.name, c.target_leads, c.collected_leads, q.status
            FROM queue q JOIN campaigns c ON q.campaign_id = c.id ORDER BY q.id
        """)
        queue_items = c.fetchall()
    if queue_items:
        for qi in queue_items:
            st.write(f"- {qi[1]}: {qi[3]}/{qi[2]} leads, status {qi[4]}")
    else:
        st.info("Queue is empty.")
    camp_options = get_all_campaigns()
    camp_options = camp_options[camp_options["status"] == "pending"]
    if not camp_options.empty:
        selected_camp = st.selectbox(
            "Select campaign to add to queue",
            camp_options["id"].tolist(),
            format_func=lambda x: f"{x}: {camp_options[camp_options['id']==x]['name'].iloc[0]}"
        )
        if st.button("Add to Queue"):
            add_to_queue(selected_camp)
            st.success(f"Campaign {selected_camp} added to queue")
            st.rerun()
    else:
        st.info("No pending campaigns.")
    if st.button("🚀 Start Queue Processing", type="primary"):
        if not deepseek_key or not serper_key:
            st.error("DeepSeek and Serper keys required")
        else:
            st.session_state.running = True
            st.rerun()

with tab4:
    st.subheader("Leads per Campaign")
    all_camps = get_all_campaigns()
    if not all_camps.empty:
        selected_camp_id = st.selectbox(
            "Select Campaign",
            all_camps["id"].tolist(),
            format_func=lambda x: f"{x}: {all_camps[all_camps['id']==x]['name'].iloc[0]}"
        )
        if selected_camp_id:
            leads_df = get_campaign_leads(selected_camp_id)
            if not leads_df.empty:
                st.dataframe(
                    leads_df[["domain","company","person","role","email","email_status",
                               "score","tier","country","icebreaker","tech_gap"]],
                    use_container_width=True
                )
                col1, col2 = st.columns(2)
                with col1:
                    csv = leads_df.to_csv(index=False).encode("utf-8")
                    st.download_button("📥 Download CSV", csv,
                                       f"campaign_{selected_camp_id}_leads.csv", "text/csv")
                with col2:
                    user_id = st.text_input("Target User ID", value="69d0df35532e93c9697f66ea",
                                            key="api_user_id")
                    if st.button("📤 Send to API"):
                        send_df = leads_df.copy()
                        send_df["name"] = send_df["person"]
                        send_df["phone"] = send_df["phone"].fillna("")
                        send_df = send_df[["name","email","phone","country","company"]]
                        csv_data = send_df.to_csv(index=False).encode("utf-8")
                        url_api = f"https://account-csv-bridge.emergent.host/api/leads/{user_id}/upload"
                        try:
                            resp = requests.post(url_api, files={"file": ("leads.csv", csv_data, "text/csv")}, timeout=30)
                            if resp.status_code == 200:
                                st.success(f"✅ Sent {len(send_df)} leads")
                                st.json(resp.json())
                            else:
                                st.error(f"API error {resp.status_code}")
                        except Exception as e:
                            st.error(f"Upload failed: {e}")
            else:
                st.info("No leads found.")
    else:
        st.info("No campaigns available.")

with tab5:
    st.subheader("📈 Enrich Existing CSV")
    uploaded_file = st.file_uploader("Choose CSV (needs `domain` column)", type=["csv"], key="enrich_csv")
    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            if "domain" not in df.columns:
                st.error("CSV must have 'domain' column")
            else:
                st.dataframe(df.head())
                if st.button("🚀 Start Enrichment", type="primary"):
                    if not deepseek_key or not serper_key:
                        st.error("DeepSeek and Serper keys required")
                    else:
                        domains = df["domain"].dropna().unique().tolist()
                        enrich_progress = st.progress(0, text=f"0/{len(domains)} done")
                        enrich_status   = st.empty()
                        enrich_status.info(f"Знайдено {len(domains)} доменів...")
                        cfg_enrich = {
                            "deepseek_key": deepseek_key, "serper_key": serper_key,
                            "prospeo_key": prospeo_key, "hunter_key": hunter_key,
                            "millionverifier_key": millionverifier_key if use_millionverifier else "",
                            "threads": parallel, "scrape_depth": scrape_depth,
                            "bruteforce": bruteforce,
                            "proxy": proxy_url if use_proxy else None,
                            "target_role": target_role, "best_contact_role": best_contact_role,
                        }
                        result_holder, done_count = [], [0]

                        async def run_enrichment():
                            sem = asyncio.Semaphore(parallel)
                            async with async_playwright() as pw:
                                browser = await pw.chromium.launch(
                                    headless=True,
                                    args=["--no-sandbox","--disable-dev-shm-usage",
                                          "--disable-gpu","--disable-images"]
                                )
                                async def _track(d):
                                    r = await enrich_one_domain(d, cfg_enrich, browser)
                                    done_count[0] += 1
                                    return r
                                results = await asyncio.gather(*[_track(d) for d in domains])
                                await browser.close()
                                return results

                        def thread_fn():
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)
                            result_holder.extend(loop.run_until_complete(run_enrichment()))

                        thread = threading.Thread(target=thread_fn)
                        thread.start()
                        total_d = len(domains)
                        while thread.is_alive():
                            time.sleep(1.5)
                            _sync_to_session()
                            _render_logs()
                            pct = min(done_count[0] / total_d, 1.0) if total_d else 1.0
                            enrich_progress.progress(pct, text=f"{done_count[0]}/{total_d} done")
                        enrich_progress.progress(1.0, text="✅ Done")
                        enrich_status.success(f"Збагачено {len(result_holder)} доменів")
                        _sync_to_session()
                        _render_logs()
                        merged = df.merge(pd.DataFrame(result_holder), on="domain", how="left")
                        st.session_state.enrichment_df = merged
                        st.dataframe(merged.head(10))
                        st.download_button("📥 Download Enriched CSV",
                                           merged.to_csv(index=False).encode("utf-8"),
                                           "enriched_leads.csv", "text/csv")
        except Exception as e:
            st.error(f"Error: {e}")

with tab6:
    st.subheader("📧 MillionVerifier — Масова перевірка")
    mv_col1, mv_col2 = st.columns(2)
    with mv_col1:
        mv_emails_raw = st.text_area("Email-адреси (по одній на рядок)", height=200,
                                     placeholder="john@example.com\ninfo@company.de")
    with mv_col2:
        mv_csv_file = st.file_uploader("Або CSV з колонкою email", type=["csv"], key="mv_csv")
    mv_key_override = st.text_input("MillionVerifier API Key",
                                    value=millionverifier_key if use_millionverifier else "",
                                    type="password", key="mv_key_tab")
    if st.button("🔍 Перевірити emails", type="primary"):
        emails_to_check = []
        if mv_emails_raw.strip():
            emails_to_check = [e.strip() for e in mv_emails_raw.strip().splitlines() if e.strip()]
        elif mv_csv_file:
            mv_df = pd.read_csv(mv_csv_file)
            if "email" in mv_df.columns:
                emails_to_check = mv_df["email"].dropna().unique().tolist()
            else:
                st.error("CSV не містить колонки 'email'")
        if not emails_to_check:
            st.warning("Введіть email-адреси або завантажте CSV")
        elif not mv_key_override:
            st.error("Потрібен MillionVerifier API ключ")
        else:
            mv_results, mv_progress = [], st.progress(0, text="Перевіряємо...")
            total_mv = len(emails_to_check)
            for i, em in enumerate(emails_to_check):
                status = verify_email_millionverifier(em, mv_key_override)
                mv_results.append({
                    "email": em, "mv_status": status,
                    "deliverable": "✅" if is_email_deliverable(status) else "❌"
                })
                _buf_log(f"📧 MV {em}: {status}", "info")
                _sync_to_session()
                _render_logs()
                mv_progress.progress((i+1)/total_mv, text=f"{i+1}/{total_mv} перевірено")
                time.sleep(0.1)
            mv_progress.progress(1.0, text="✅ Done")
            mv_df_result = pd.DataFrame(mv_results)
            valid_count = mv_df_result[mv_df_result["deliverable"]=="✅"].shape[0]
            st.success(f"**{valid_count}/{total_mv}** emails є доставними")
            c1, c2, c3 = st.columns(3)
            c1.metric("✅ Deliverable", valid_count)
            c2.metric("❌ Invalid", mv_df_result[mv_df_result["deliverable"]=="❌"].shape[0])
            c3.metric("❓ Unknown", mv_df_result[mv_df_result["mv_status"].str.contains("UNKNOWN|CATCH", na=False)].shape[0])
            st.dataframe(mv_df_result, use_container_width=True)
            st.download_button("📥 Завантажити", mv_df_result.to_csv(index=False).encode("utf-8"),
                               "mv_results.csv", "text/csv")

# ======================== CAMPAIGN PROGRESS ========================
prog_ph = st.empty()

def _redraw_ui():
    _sync_to_session()
    _render_logs()
    if st.session_state.active_campaign_id:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT target_leads, collected_leads FROM campaigns WHERE id=?",
                      (st.session_state.active_campaign_id,))
            row = c.fetchone()
            if row:
                t, cl = row
                prog_ph.progress(min(1.0, cl/t) if t > 0 else 0.0,
                                 text=f"Campaign: {cl}/{t} leads")
    else:
        prog_ph.empty()

# ======================== MAIN LOOP ========================
if st.session_state.get("running", False):
    campaign = get_next_campaign_from_queue()
    if not campaign:
        st.session_state.running = False
        st.success("Queue is empty. All campaigns completed.")
        st.rerun()
    else:
        st.session_state.active_campaign_id = campaign["id"]
        st.info(f"Processing: {campaign['name']} → {campaign['target_leads']} leads")
        cfg = {
            "deepseek_key": deepseek_key, "serper_key": serper_key,
            "prospeo_key": prospeo_key, "hunter_key": hunter_key,
            "millionverifier_key": millionverifier_key if use_millionverifier else "",
            "threads": parallel, "scrape_depth": scrape_depth,
            "min_score": min_score, "only_whales": only_whales,
            "bruteforce": bruteforce,
            "target_role": target_role, "best_contact_role": best_contact_role,
            "proxy": proxy_url if use_proxy else None,
            "target_countries": target_countries,
            "campaign_id": campaign["id"],
        }

        def run_async():
            try:
                asyncio.run(run_campaign(campaign, cfg))
            except Exception as e:
                _buf_log(f"Thread error: {e}", "error")

        thread = threading.Thread(target=run_async)
        thread.start()
        while thread.is_alive():
            time.sleep(2)
            _redraw_ui()
            with sqlite3.connect(DB_PATH) as conn:
                c = conn.cursor()
                c.execute("SELECT status FROM campaigns WHERE id=?", (campaign["id"],))
                row = c.fetchone()
                if row and row[0] in ("completed", "failed"):
                    break
        st.session_state.active_campaign_id = None
        st.session_state.running = False
        st.rerun()
else:
    if st.session_state.logs:
        _render_logs()