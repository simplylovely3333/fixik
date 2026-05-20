from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timezone, timedelta

ALMATY_TZ = timezone(timedelta(hours=5))
from typing import Optional
import httpx
import sqlite3
import hashlib
import secrets
import re
import os

app = FastAPI(title="FixiK API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

DB_PATH = os.getenv("DB_PATH", "fixik.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            device TEXT NOT NULL,
            description TEXT NOT NULL,
            visit_date TEXT,
            visit_time TEXT,
            status TEXT DEFAULT 'new',
            created_at TEXT NOT NULL
        )
    """)
    # Migration: add visit_date/visit_time columns if they don't exist yet
    try:
        conn.execute("ALTER TABLE requests ADD COLUMN visit_date TEXT")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE requests ADD COLUMN visit_time TEXT")
    except Exception:
        pass
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# ===== ВАЛИДАЦИЯ =====
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_valid_email(email: str) -> bool:
    """Email корректен, если есть текст до и после @, а после точки в домене."""
    return bool(EMAIL_RE.match(email))


def is_valid_phone(phone: str) -> bool:
    """Телефон корректен, если в нём ровно 11 цифр и он начинается с 7 или 8."""
    digits = re.sub(r"\D", "", phone)
    return len(digits) == 11 and digits[0] in "78"


init_db()


class RepairRequest(BaseModel):
    name: str
    phone: str
    device: str
    description: str
    date: Optional[str] = None
    time: Optional[str] = None


class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


MONTHS_RU = [
    "января", "февраля", "марта", "апреля", "мая", "июня",
    "июля", "августа", "сентября", "октября", "ноября", "декабря"
]


def format_date_ru(date_str: str) -> str:
    try:
        y, m, d = date_str.split("-")
        return f"{int(d)} {MONTHS_RU[int(m) - 1]} {y}"
    except Exception:
        return date_str


async def send_telegram(request: RepairRequest, request_id: int):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return

    visit_line = ""
    if request.date and request.time:
        visit_line = f"\n📅 <b>Запись на:</b> {format_date_ru(request.date)} в {request.time}"
    elif request.date:
        visit_line = f"\n📅 <b>Дата визита:</b> {format_date_ru(request.date)}"

    text = (
        f"🔧 <b>Новая заявка #{request_id}</b>\n\n"
        f"👤 <b>Имя:</b> {request.name}\n"
        f"📞 <b>Телефон:</b> {request.phone}\n"
        f"💻 <b>Устройство:</b> {request.device}\n"
        f"📝 <b>Проблема:</b> {request.description}"
        f"{visit_line}\n\n"
        f"🕐 {datetime.now(ALMATY_TZ).strftime('%d.%m.%Y %H:%M')}"
    )

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    async with httpx.AsyncClient() as client:
        await client.post(url, json={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": text,
            "parse_mode": "HTML"
        })


@app.post("/auth/register", status_code=201)
def register(data: RegisterRequest):
    name = data.name.strip()
    email = data.email.strip().lower()
    if len(name) < 2:
        raise HTTPException(400, "Введите имя (минимум 2 символа)")
    if not is_valid_email(email):
        raise HTTPException(400, "Введите корректный email")
    if len(data.password) < 6:
        raise HTTPException(400, "Пароль должен быть минимум 6 символов")
    conn = sqlite3.connect(DB_PATH)
    existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(400, "Пользователь с таким email уже существует")
    conn.execute(
        "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (name, email, hash_password(data.password), datetime.now(ALMATY_TZ).isoformat())
    )
    conn.commit()
    conn.close()
    return {"name": name, "email": email, "token": secrets.token_hex(32)}


@app.post("/auth/login")
def login(data: LoginRequest):
    email = data.email.strip().lower()
    if not is_valid_email(email):
        raise HTTPException(400, "Введите корректный email")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    user = conn.execute(
        "SELECT * FROM users WHERE email = ? AND password_hash = ?",
        (email, hash_password(data.password))
    ).fetchone()
    conn.close()
    if not user:
        raise HTTPException(401, "Неверный email или пароль")
    return {"name": user["name"], "email": user["email"], "token": secrets.token_hex(32)}


@app.post("/api/requests", status_code=201)
async def create_request(data: RepairRequest):
    data.name = data.name.strip()
    data.description = data.description.strip()
    if len(data.name) < 2:
        raise HTTPException(400, "Введите имя (минимум 2 символа)")
    if not is_valid_phone(data.phone):
        raise HTTPException(400, "Введите корректный номер телефона")
    if not data.device.strip():
        raise HTTPException(400, "Выберите тип устройства")
    if len(data.description) < 5:
        raise HTTPException(400, "Опишите проблему подробнее (минимум 5 символов)")

    created_at = datetime.now(ALMATY_TZ).isoformat()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute(
        "INSERT INTO requests (name, phone, device, description, visit_date, visit_time, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (data.name, data.phone, data.device, data.description, data.date, data.time, created_at)
    )
    request_id = cursor.lastrowid
    conn.commit()
    conn.close()

    await send_telegram(data, request_id)

    return {"id": request_id, "message": "Заявка принята"}


@app.get("/api/requests")
def get_requests():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM requests ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.patch("/api/requests/{request_id}/status")
def update_status(request_id: int, status: str):
    allowed = {"new", "in_progress", "done", "cancelled"}
    if status not in allowed:
        raise HTTPException(400, "Недопустимый статус")

    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE requests SET status = ? WHERE id = ?", (status, request_id))
    conn.commit()
    conn.close()
    return {"ok": True}
