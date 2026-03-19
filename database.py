"""
database.py — SQLite backend for Medicine Reminder App
Uses Python's built-in sqlite3 — no MindsDB needed for storage.
Tables: users, sessions, profiles, medicines, dose_logs, health_vitals
"""

import sqlite3
import os
import json
import hashlib
import secrets
from datetime import datetime, date, timedelta

# ── Database file path ────────────────────────────────────────────────────────
BASE_DIR = os.getenv(
    "MED_BASE_DIR",
    r"C:\Users\sande\Downloads\medicine reminder"
)
DB_FILE = os.path.join(BASE_DIR, "med_reminder.db")


# ── Connection helper ─────────────────────────────────────────────────────────
def get_conn():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ── Password helpers ──────────────────────────────────────────────────────────
def _hash_password(password: str, salt: str = None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return h, salt


def _verify_password(password: str, stored_hash: str, salt: str) -> bool:
    h, _ = _hash_password(password, salt)
    return h == stored_hash


# ── Schema bootstrap ──────────────────────────────────────────────────────────
def init_db():
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         TEXT PRIMARY KEY,
            username   TEXT NOT NULL UNIQUE,
            email      TEXT,
            pwd_hash   TEXT NOT NULL,
            pwd_salt   TEXT NOT NULL,
            created_at TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            username   TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS profiles (
            id         TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            name       TEXT NOT NULL,
            color      TEXT NOT NULL,
            created_at TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS medicines (
            id         INTEGER PRIMARY KEY,
            profile_id TEXT NOT NULL,
            user_id    TEXT NOT NULL,
            name       TEXT NOT NULL,
            dosage     TEXT NOT NULL,
            times      TEXT NOT NULL,
            created_at TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS dose_logs (
            id         INTEGER PRIMARY KEY,
            med_id     INTEGER NOT NULL,
            profile_id TEXT NOT NULL,
            user_id    TEXT NOT NULL,
            log_date   TEXT NOT NULL,
            log_time   TEXT NOT NULL,
            status     TEXT NOT NULL,
            logged_at  TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS health_vitals (
            id          INTEGER PRIMARY KEY,
            profile_id  TEXT NOT NULL,
            user_id     TEXT NOT NULL,
            metric      TEXT NOT NULL,
            value       REAL NOT NULL,
            unit        TEXT,
            notes       TEXT,
            recorded_at TEXT
        )
    """)

    conn.commit()
    conn.close()
    print(f"  Database ready: {DB_FILE}")


# ── Auth ──────────────────────────────────────────────────────────────────────
def register_user(username: str, password: str, email: str = ""):
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT id FROM users WHERE username=?", (username,)
        ).fetchone()
        if row:
            raise ValueError("Username already taken")

        uid = "user_" + secrets.token_hex(8)
        now = datetime.utcnow().isoformat()
        pwd_hash, pwd_salt = _hash_password(password)

        conn.execute(
            "INSERT INTO users (id,username,email,pwd_hash,pwd_salt,created_at) VALUES (?,?,?,?,?,?)",
            (uid, username, email, pwd_hash, pwd_salt, now)
        )
        conn.commit()
        return {"id": uid, "username": username}
    finally:
        conn.close()


def login_user(username: str, password: str):
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()
        if not row:
            raise ValueError("Invalid username or password")

        if not _verify_password(password, row["pwd_hash"], row["pwd_salt"]):
            raise ValueError("Invalid username or password")

        token      = secrets.token_hex(32)
        now        = datetime.utcnow()
        expires_at = (now + timedelta(days=30)).isoformat()

        conn.execute(
            "INSERT INTO sessions (token,user_id,username,expires_at,created_at) VALUES (?,?,?,?,?)",
            (token, row["id"], username, expires_at, now.isoformat())
        )
        conn.commit()
        return {"token": token, "user_id": row["id"], "username": username}
    finally:
        conn.close()


def validate_token(token: str):
    if not token:
        return None
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM sessions WHERE token=?", (token,)
        ).fetchone()
        if not row:
            return None
        if datetime.utcnow().isoformat() > row["expires_at"]:
            conn.execute("DELETE FROM sessions WHERE token=?", (token,))
            conn.commit()
            return None
        return {"user_id": row["user_id"], "username": row["username"]}
    finally:
        conn.close()


def logout_user(token: str):
    conn = get_conn()
    try:
        conn.execute("DELETE FROM sessions WHERE token=?", (token,))
        conn.commit()
    finally:
        conn.close()


def change_password(user_id: str, old_password: str, new_password: str):
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE id=?", (user_id,)
        ).fetchone()
        if not row:
            raise ValueError("User not found")
        if not _verify_password(old_password, row["pwd_hash"], row["pwd_salt"]):
            raise ValueError("Current password is incorrect")
        new_hash, new_salt = _hash_password(new_password)
        conn.execute(
            "UPDATE users SET pwd_hash=?, pwd_salt=? WHERE id=?",
            (new_hash, new_salt, user_id)
        )
        conn.commit()
    finally:
        conn.close()


# ── Profiles ──────────────────────────────────────────────────────────────────
def get_profiles_for_user(user_id: str):
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM profiles WHERE user_id=? ORDER BY created_at", (user_id,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def create_profile(user_id: str, profile_id: str, name: str, color: str):
    conn = get_conn()
    try:
        now = datetime.utcnow().isoformat()
        conn.execute(
            "INSERT INTO profiles (id,user_id,name,color,created_at) VALUES (?,?,?,?,?)",
            (profile_id, user_id, name, color, now)
        )
        conn.commit()
        return {"id": profile_id, "user_id": user_id, "name": name, "color": color, "created_at": now}
    finally:
        conn.close()


def delete_profile(user_id: str, profile_id: str):
    conn = get_conn()
    try:
        conn.execute("DELETE FROM dose_logs    WHERE profile_id=? AND user_id=?", (profile_id, user_id))
        conn.execute("DELETE FROM medicines    WHERE profile_id=? AND user_id=?", (profile_id, user_id))
        conn.execute("DELETE FROM health_vitals WHERE profile_id=? AND user_id=?", (profile_id, user_id))
        conn.execute("DELETE FROM profiles     WHERE id=?          AND user_id=?", (profile_id, user_id))
        conn.commit()
    finally:
        conn.close()


# ── Medicines ─────────────────────────────────────────────────────────────────
def get_medicines_for_profile(user_id: str, profile_id: str):
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM medicines WHERE profile_id=? AND user_id=? ORDER BY created_at",
            (profile_id, user_id)
        ).fetchall()
        result = []
        for row in rows:
            r = dict(row)
            try:    r["times"] = json.loads(r["times"])
            except: r["times"] = []
            result.append(r)
        return result
    finally:
        conn.close()


def get_all_medicines_for_user(user_id: str):
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM medicines WHERE user_id=?", (user_id,)
        ).fetchall()
        result = []
        for row in rows:
            r = dict(row)
            try:    r["times"] = json.loads(r["times"])
            except: r["times"] = []
            result.append(r)
        return result
    finally:
        conn.close()


def create_medicine(user_id: str, profile_id: str, name: str, dosage: str, times: list):
    conn = get_conn()
    try:
        med_id     = int(datetime.utcnow().timestamp() * 1000)
        now        = datetime.utcnow().isoformat()
        times_json = json.dumps(times)
        conn.execute(
            "INSERT INTO medicines (id,profile_id,user_id,name,dosage,times,created_at) VALUES (?,?,?,?,?,?,?)",
            (med_id, profile_id, user_id, name, dosage, times_json, now)
        )
        conn.commit()
        return {"id": med_id, "profile_id": profile_id, "name": name,
                "dosage": dosage, "times": times, "created_at": now}
    finally:
        conn.close()


def delete_medicine(user_id: str, med_id: int):
    conn = get_conn()
    try:
        conn.execute("DELETE FROM dose_logs WHERE med_id=? AND user_id=?", (med_id, user_id))
        conn.execute("DELETE FROM medicines  WHERE id=?     AND user_id=?", (med_id, user_id))
        conn.commit()
    finally:
        conn.close()


# ── Dose logs ─────────────────────────────────────────────────────────────────
def log_dose(user_id: str, med_id: int, profile_id: str, log_date: str, log_time: str, status: str):
    conn = get_conn()
    try:
        log_id = int(datetime.utcnow().timestamp() * 1000)
        now    = datetime.utcnow().isoformat()
        conn.execute(
            "DELETE FROM dose_logs WHERE med_id=? AND log_date=? AND log_time=? AND user_id=?",
            (med_id, log_date, log_time, user_id)
        )
        conn.execute(
            "INSERT INTO dose_logs (id,med_id,profile_id,user_id,log_date,log_time,status,logged_at) VALUES (?,?,?,?,?,?,?,?)",
            (log_id, med_id, profile_id, user_id, log_date, log_time, status, now)
        )
        conn.commit()
        return {"id": log_id, "med_id": med_id, "log_date": log_date,
                "log_time": log_time, "status": status}
    finally:
        conn.close()


def get_medicine_analytics(user_id: str, med_id: int, days: int = 30):
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM medicines WHERE id=? AND user_id=?", (med_id, user_id)
        ).fetchone()
        if not row:
            return None
        med = dict(row)
        try:    med_times = json.loads(med["times"])
        except: med_times = []

        since = (date.today() - timedelta(days=days)).isoformat()
        logs  = conn.execute(
            "SELECT * FROM dose_logs WHERE med_id=? AND user_id=? AND log_date>=? ORDER BY log_date,log_time",
            (med_id, user_id, since)
        ).fetchall()
        log_map = {(l["log_date"], l["log_time"]): l["status"] for l in logs}

        today_date = date.today()
        daily      = []
        total_expected = total_taken = total_skipped = 0

        for i in range(days - 1, -1, -1):
            d  = (today_date - timedelta(days=i)).isoformat()
            dt = sum(1 for t in med_times if log_map.get((d, t)) == "taken")
            ds = sum(1 for t in med_times if log_map.get((d, t)) == "skipped")
            daily.append({"date": d, "taken": dt, "skipped": ds,
                          "unlogged": len(med_times) - dt - ds, "expected": len(med_times)})
            total_expected += len(med_times)
            total_taken    += dt
            total_skipped  += ds

        streak = 0
        for day in reversed(daily):
            if day["expected"] > 0 and day["taken"] == day["expected"]:
                streak += 1
            else:
                break

        adherence_pct = round((total_taken / total_expected * 100) if total_expected else 0, 1)
        return {
            "med_id": med_id, "med_name": med["name"], "med_dosage": med["dosage"],
            "days": days, "total_expected": total_expected, "total_taken": total_taken,
            "total_skipped": total_skipped,
            "total_unlogged": total_expected - total_taken - total_skipped,
            "adherence_pct": adherence_pct, "streak_days": streak, "daily": daily
        }
    finally:
        conn.close()


# ── Health vitals ─────────────────────────────────────────────────────────────
VITAL_THRESHOLDS = {
    "bp_sys":        {"unit": "mmHg",  "low": 90,   "high": 140,  "label": "BP Systolic"},
    "bp_dia":        {"unit": "mmHg",  "low": 60,   "high": 90,   "label": "BP Diastolic"},
    "sugar_fasting": {"unit": "mg/dL", "low": 70,   "high": 100,  "label": "Blood Sugar (Fasting)"},
    "sugar_pp":      {"unit": "mg/dL", "low": 70,   "high": 140,  "label": "Blood Sugar (Post-Meal)"},
    "heart_rate":    {"unit": "bpm",   "low": 60,   "high": 100,  "label": "Heart Rate"},
    "spo2":          {"unit": "%",     "low": 95,   "high": 100,  "label": "SpO2"},
    "weight":        {"unit": "kg",    "low": None, "high": None, "label": "Weight"},
    "temperature":   {"unit": "C",     "low": 36.1, "high": 37.2, "label": "Temperature"},
    "cholesterol":   {"unit": "mg/dL", "low": None, "high": 200,  "label": "Total Cholesterol"},
    "hba1c":         {"unit": "%",     "low": None, "high": 5.7,  "label": "HbA1c"},
}


def log_vital(user_id: str, profile_id: str, metric: str, value: float, notes: str = ""):
    conn = get_conn()
    try:
        vid  = int(datetime.utcnow().timestamp() * 1000)
        now  = datetime.utcnow().isoformat()
        unit = VITAL_THRESHOLDS.get(metric, {}).get("unit", "")
        conn.execute(
            "INSERT INTO health_vitals (id,profile_id,user_id,metric,value,unit,notes,recorded_at) VALUES (?,?,?,?,?,?,?,?)",
            (vid, profile_id, user_id, metric, value, unit, notes, now)
        )
        conn.commit()
        return {"id": vid, "profile_id": profile_id, "metric": metric,
                "value": value, "unit": unit, "notes": notes, "recorded_at": now}
    finally:
        conn.close()


def get_vitals_for_profile(user_id: str, profile_id: str, days: int = 30):
    conn = get_conn()
    try:
        since = (datetime.utcnow() - timedelta(days=days)).isoformat()
        rows  = conn.execute(
            "SELECT * FROM health_vitals WHERE profile_id=? AND user_id=? AND recorded_at>=? ORDER BY recorded_at DESC",
            (profile_id, user_id, since)
        ).fetchall()

        result = []
        for row in rows:
            r      = dict(row)
            thresh = VITAL_THRESHOLDS.get(r["metric"], {})
            v, lo, hi = float(r["value"]), thresh.get("low"), thresh.get("high")
            if   lo is not None and v < lo: r["status"] = "low"
            elif hi is not None and v > hi: r["status"] = "high"
            else:                           r["status"] = "normal"
            r["label"] = thresh.get("label", r["metric"])
            r["unit"]  = thresh.get("unit",  r.get("unit", ""))
            result.append(r)

        grouped = {}
        for r in result:
            grouped.setdefault(r["metric"], []).append(r)

        return {"vitals": result, "grouped": grouped, "thresholds": VITAL_THRESHOLDS}
    finally:
        conn.close()


def delete_vital(user_id: str, vital_id: int):
    conn = get_conn()
    try:
        conn.execute(
            "DELETE FROM health_vitals WHERE id=? AND user_id=?", (vital_id, user_id)
        )
        conn.commit()
    finally:
        conn.close()
