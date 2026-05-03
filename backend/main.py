from fastapi import FastAPI, HTTPException, Depends, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional
import sqlite3
import os
from datetime import datetime
from pathlib import Path
import bcrypt
from jose import JWTError, jwt

app = FastAPI(title="Portfolio Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = os.getenv("DB_PATH", "/data/portfolio.db")
SECRET_KEY = os.getenv("SECRET_KEY", "change-this-to-a-random-secret-min-32-chars")
ALGORITHM = "HS256"
COOKIE_NAME = "portfolio_session"


# ==================== DATABASE ====================

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            date TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            value REAL NOT NULL,
            invested REAL NOT NULL DEFAULT 0,
            FOREIGN KEY (snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS asset_definitions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)
    conn.commit()
    conn.close()

init_db()

# ==================== AUTH HELPERS ====================

def create_token(user_id: int, username: str, is_admin: bool) -> str:
    return jwt.encode(
        {"sub": str(user_id), "username": username, "is_admin": is_admin},
        SECRET_KEY, algorithm=ALGORITHM
    )

def get_current_user(request: Request) -> dict:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {
            "id": int(payload["sub"]),
            "username": payload["username"],
            "is_admin": payload.get("is_admin", False)
        }
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_admin(user=Depends(get_current_user)) -> dict:
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admin required")
    return user

# ==================== MODELS ====================

class AssetIn(BaseModel):
    name: str
    type: str
    value: float
    invested: float = 0.0

class SnapshotIn(BaseModel):
    date: str
    assets: List[AssetIn]

class AssetDefIn(BaseModel):
    name: str
    type: str

class AuthIn(BaseModel):
    username: str
    password: str

class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str

class AdminSetPasswordIn(BaseModel):
    new_password: str

class CreateUserIn(BaseModel):
    username: str
    password: str
    is_admin: bool = False

# ==================== SETUP (first run) ====================

@app.get("/auth/setup-required")
def setup_required():
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    conn.close()
    return {"setup_required": count == 0}

@app.post("/auth/setup")
def setup(data: AuthIn, response: Response):
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count > 0:
        conn.close()
        raise HTTPException(status_code=400, detail="Setup already completed")
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, 1, ?)",
        (data.username, bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode(), datetime.now().isoformat())
    )
    user_id = cur.lastrowid
    conn.commit()
    conn.close()
    token = create_token(user_id, data.username, True)
    response.set_cookie(COOKIE_NAME, token, httponly=True, samesite="lax", max_age=365*24*3600)
    return {"username": data.username, "is_admin": True}

# ==================== AUTH ENDPOINTS ====================

@app.post("/auth/login")
def login(data: AuthIn, response: Response):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (data.username,)).fetchone()
    conn.close()
    if not user or not bcrypt.checkpw(data.password.encode(), user["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Nieprawidłowy login lub hasło")
    token = create_token(user["id"], user["username"], bool(user["is_admin"]))
    response.set_cookie(COOKIE_NAME, token, httponly=True, samesite="lax", max_age=365*24*3600)
    return {"username": user["username"], "is_admin": bool(user["is_admin"])}

@app.post("/auth/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE_NAME)
    return {"ok": True}

@app.get("/auth/me")
def me(user=Depends(get_current_user)):
    return {"id": user["id"], "username": user["username"], "is_admin": user["is_admin"]}

@app.post("/auth/change-password")
def change_password(data: ChangePasswordIn, user=Depends(get_current_user)):
    conn = get_db()
    row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user["id"],)).fetchone()
    if not bcrypt.checkpw(data.current_password.encode(), row["password_hash"].encode()):
        conn.close()
        raise HTTPException(status_code=401, detail="Nieprawidłowe obecne hasło")
    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (bcrypt.hashpw(data.new_password.encode(), bcrypt.gensalt()).decode(), user["id"])
    )
    conn.commit()
    conn.close()
    return {"ok": True}

# ==================== ADMIN: USER MANAGEMENT ====================

@app.get("/admin/users")
def list_users(user=Depends(require_admin)):
    conn = get_db()
    users = conn.execute(
        "SELECT id, username, is_admin, created_at FROM users ORDER BY id"
    ).fetchall()
    result = []
    for u in users:
        snap_count = conn.execute(
            "SELECT COUNT(*) FROM snapshots WHERE user_id = ?", (u["id"],)
        ).fetchone()[0]
        result.append({
            "id": u["id"],
            "username": u["username"],
            "is_admin": bool(u["is_admin"]),
            "created_at": u["created_at"],
            "snapshot_count": snap_count
        })
    conn.close()
    return result

@app.post("/admin/users", status_code=201)
def create_user(data: CreateUserIn, user=Depends(require_admin)):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)",
            (data.username, bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode(), int(data.is_admin), datetime.now().isoformat())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Użytkownik '{data.username}' już istnieje")
    conn.close()
    return {"username": data.username, "is_admin": data.is_admin}

@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int, user=Depends(require_admin)):
    if user_id == user["id"]:
        raise HTTPException(status_code=400, detail="Nie możesz usunąć własnego konta")
    conn = get_db()
    target = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    conn.execute("DELETE FROM asset_definitions WHERE user_id = ?", (user_id,))
    conn.execute(
        "DELETE FROM assets WHERE snapshot_id IN (SELECT id FROM snapshots WHERE user_id = ?)",
        (user_id,)
    )
    conn.execute("DELETE FROM snapshots WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return {"deleted": user_id}

@app.put("/admin/users/{user_id}/password")
def admin_set_password(user_id: int, data: AdminSetPasswordIn, user=Depends(require_admin)):
    conn = get_db()
    target = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (bcrypt.hashpw(data.new_password.encode(), bcrypt.gensalt()).decode(), user_id)
    )
    conn.commit()
    conn.close()
    return {"ok": True}

@app.put("/admin/users/{user_id}/toggle-admin")
def toggle_admin(user_id: int, data: dict, user=Depends(require_admin)):
    if user_id == user["id"]:
        raise HTTPException(status_code=400, detail="Nie możesz zmienić własnej roli")
    conn = get_db()
    conn.execute(
        "UPDATE users SET is_admin = ? WHERE id = ?",
        (int(data.get("is_admin", False)), user_id)
    )
    conn.commit()
    conn.close()
    return {"ok": True}

# ==================== SNAPSHOTS ====================

@app.get("/api/snapshots")
def get_snapshots(user=Depends(get_current_user)):
    conn = get_db()
    snapshots = conn.execute(
        "SELECT * FROM snapshots WHERE user_id = ? ORDER BY date ASC", (user["id"],)
    ).fetchall()
    result = []
    for snap in snapshots:
        assets = conn.execute(
            "SELECT * FROM assets WHERE snapshot_id = ?", (snap["id"],)
        ).fetchall()
        result.append({
            "id": snap["id"],
            "date": snap["date"],
            "created_at": snap["created_at"],
            "assets": [dict(a) for a in assets]
        })
    conn.close()
    return result

@app.post("/api/snapshots", status_code=201)
def create_snapshot(data: SnapshotIn, user=Depends(get_current_user)):
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO snapshots (user_id, date, created_at) VALUES (?, ?, ?)",
        (user["id"], data.date, datetime.now().isoformat())
    )
    snap_id = cur.lastrowid
    for asset in data.assets:
        conn.execute(
            "INSERT INTO assets (snapshot_id, name, type, value, invested) VALUES (?, ?, ?, ?, ?)",
            (snap_id, asset.name, asset.type, asset.value, asset.invested)
        )
    conn.commit()
    conn.close()
    return {"id": snap_id, "date": data.date}

@app.put("/api/snapshots/{snap_id}")
def update_snapshot(snap_id: int, data: SnapshotIn, user=Depends(get_current_user)):
    conn = get_db()
    snap = conn.execute(
        "SELECT id FROM snapshots WHERE id = ? AND user_id = ?", (snap_id, user["id"])
    ).fetchone()
    if not snap:
        conn.close()
        raise HTTPException(status_code=404, detail="Snapshot not found")
    conn.execute("UPDATE snapshots SET date = ? WHERE id = ?", (data.date, snap_id))
    conn.execute("DELETE FROM assets WHERE snapshot_id = ?", (snap_id,))
    for asset in data.assets:
        conn.execute(
            "INSERT INTO assets (snapshot_id, name, type, value, invested) VALUES (?, ?, ?, ?, ?)",
            (snap_id, asset.name, asset.type, asset.value, asset.invested)
        )
    conn.commit()
    conn.close()
    return {"id": snap_id, "date": data.date}

@app.delete("/api/snapshots/{snap_id}")
def delete_snapshot(snap_id: int, user=Depends(get_current_user)):
    conn = get_db()
    snap = conn.execute(
        "SELECT id FROM snapshots WHERE id = ? AND user_id = ?", (snap_id, user["id"])
    ).fetchone()
    if not snap:
        conn.close()
        raise HTTPException(status_code=404, detail="Snapshot not found")
    conn.execute("DELETE FROM assets WHERE snapshot_id = ?", (snap_id,))
    conn.execute("DELETE FROM snapshots WHERE id = ?", (snap_id,))
    conn.commit()
    conn.close()
    return {"deleted": snap_id}

# ==================== ASSET DEFINITIONS ====================

DEFAULT_DEFS = [
    {"name": "IKE – WEBN", "type": "ETF (akcje)"},
    {"name": "IKZE – MSCI World", "type": "ETF (akcje)"},
    {"name": "IKZE – EM", "type": "ETF (akcje)"},
    {"name": "Maklerskie – ETF", "type": "ETF (akcje)"},
    {"name": "Obligacje EDO", "type": "Obligacje"},
    {"name": "Obligacje ROD", "type": "Obligacje"},
    {"name": "Lokata", "type": "Lokata"},
]

@app.get("/api/asset-definitions")
def get_asset_definitions(user=Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM asset_definitions WHERE user_id = ? ORDER BY id ASC", (user["id"],)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows] if rows else DEFAULT_DEFS

@app.put("/api/asset-definitions")
def save_asset_definitions(defs: List[AssetDefIn], user=Depends(get_current_user)):
    conn = get_db()
    conn.execute("DELETE FROM asset_definitions WHERE user_id = ?", (user["id"],))
    for d in defs:
        conn.execute(
            "INSERT INTO asset_definitions (user_id, name, type) VALUES (?, ?, ?)",
            (user["id"], d.name, d.type)
        )
    conn.commit()
    conn.close()
    return {"saved": len(defs)}

# ==================== EXPORT / IMPORT ====================

@app.get("/api/export")
def export_data(user=Depends(get_current_user)):
    conn = get_db()
    snapshots = conn.execute(
        "SELECT * FROM snapshots WHERE user_id = ? ORDER BY date ASC", (user["id"],)
    ).fetchall()
    result = []
    for snap in snapshots:
        assets = conn.execute(
            "SELECT name, type, value, invested FROM assets WHERE snapshot_id = ?", (snap["id"],)
        ).fetchall()
        result.append({"date": snap["date"], "assets": [dict(a) for a in assets]})
    defs = conn.execute(
        "SELECT name, type FROM asset_definitions WHERE user_id = ?", (user["id"],)
    ).fetchall()
    conn.close()
    return {
        "exported_at": datetime.now().isoformat(),
        "snapshots": result,
        "asset_definitions": [dict(d) for d in defs]
    }

@app.post("/api/import")
def import_data(data: dict, user=Depends(get_current_user)):
    conn = get_db()
    conn.execute(
        "DELETE FROM assets WHERE snapshot_id IN (SELECT id FROM snapshots WHERE user_id = ?)",
        (user["id"],)
    )
    conn.execute("DELETE FROM snapshots WHERE user_id = ?", (user["id"],))
    conn.execute("DELETE FROM asset_definitions WHERE user_id = ?", (user["id"],))
    for snap in data.get("snapshots", []):
        cur = conn.execute(
            "INSERT INTO snapshots (user_id, date, created_at) VALUES (?, ?, ?)",
            (user["id"], snap["date"], datetime.now().isoformat())
        )
        for asset in snap.get("assets", []):
            conn.execute(
                "INSERT INTO assets (snapshot_id, name, type, value, invested) VALUES (?, ?, ?, ?, ?)",
                (cur.lastrowid, asset["name"], asset["type"], asset["value"], asset.get("invested", 0))
            )
    for d in data.get("asset_definitions", []):
        conn.execute(
            "INSERT INTO asset_definitions (user_id, name, type) VALUES (?, ?, ?)",
            (user["id"], d["name"], d["type"])
        )
    conn.commit()
    conn.close()
    return {"imported": len(data.get("snapshots", []))}

# ==================== STATIC FRONTEND ====================

app.mount("/", StaticFiles(directory="/frontend", html=True), name="frontend")