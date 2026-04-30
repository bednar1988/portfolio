from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional
import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path

app = FastAPI(title="Portfolio Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = os.getenv("DB_PATH", "/data/portfolio.db")

# ==================== DATABASE ====================

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            created_at TEXT NOT NULL
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
            name TEXT NOT NULL,
            type TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()

init_db()

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

# ==================== SNAPSHOTS ====================

@app.get("/api/snapshots")
def get_snapshots():
    conn = get_db()
    snapshots = conn.execute("SELECT * FROM snapshots ORDER BY date ASC").fetchall()
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
def create_snapshot(data: SnapshotIn):
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO snapshots (date, created_at) VALUES (?, ?)",
        (data.date, datetime.now().isoformat())
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

@app.delete("/api/snapshots/{snap_id}")
def delete_snapshot(snap_id: int):
    conn = get_db()
    snap = conn.execute("SELECT id FROM snapshots WHERE id = ?", (snap_id,)).fetchone()
    if not snap:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    conn.execute("DELETE FROM assets WHERE snapshot_id = ?", (snap_id,))
    conn.execute("DELETE FROM snapshots WHERE id = ?", (snap_id,))
    conn.commit()
    conn.close()
    return {"deleted": snap_id}

# ==================== ASSET DEFINITIONS ====================

@app.get("/api/asset-definitions")
def get_asset_definitions():
    conn = get_db()
    rows = conn.execute("SELECT * FROM asset_definitions ORDER BY id ASC").fetchall()
    conn.close()
    if not rows:
        return [
            {"id": None, "name": "IKE – WEBN", "type": "ETF (akcje)"},
            {"id": None, "name": "IKZE – MSCI World", "type": "ETF (akcje)"},
            {"id": None, "name": "IKZE – EM", "type": "ETF (akcje)"},
            {"id": None, "name": "Maklerskie – ETF", "type": "ETF (akcje)"},
            {"id": None, "name": "Obligacje EDO", "type": "Obligacje"},
            {"id": None, "name": "Obligacje ROD", "type": "Obligacje"},
            {"id": None, "name": "Lokata", "type": "Lokata"},
        ]
    return [dict(r) for r in rows]

@app.put("/api/asset-definitions")
def save_asset_definitions(defs: List[AssetDefIn]):
    conn = get_db()
    conn.execute("DELETE FROM asset_definitions")
    for d in defs:
        conn.execute(
            "INSERT INTO asset_definitions (name, type) VALUES (?, ?)",
            (d.name, d.type)
        )
    conn.commit()
    conn.close()
    return {"saved": len(defs)}

# ==================== EXPORT / IMPORT ====================

@app.get("/api/export")
def export_data():
    conn = get_db()
    snapshots = conn.execute("SELECT * FROM snapshots ORDER BY date ASC").fetchall()
    result = []
    for snap in snapshots:
        assets = conn.execute(
            "SELECT name, type, value, invested FROM assets WHERE snapshot_id = ?",
            (snap["id"],)
        ).fetchall()
        result.append({
            "date": snap["date"],
            "assets": [dict(a) for a in assets]
        })
    defs = conn.execute("SELECT name, type FROM asset_definitions").fetchall()
    conn.close()
    return {
        "exported_at": datetime.now().isoformat(),
        "snapshots": result,
        "asset_definitions": [dict(d) for d in defs]
    }

@app.post("/api/import")
def import_data(data: dict):
    conn = get_db()
    conn.execute("DELETE FROM assets")
    conn.execute("DELETE FROM snapshots")
    conn.execute("DELETE FROM asset_definitions")

    for snap in data.get("snapshots", []):
        cur = conn.execute(
            "INSERT INTO snapshots (date, created_at) VALUES (?, ?)",
            (snap["date"], datetime.now().isoformat())
        )
        snap_id = cur.lastrowid
        for asset in snap.get("assets", []):
            conn.execute(
                "INSERT INTO assets (snapshot_id, name, type, value, invested) VALUES (?, ?, ?, ?, ?)",
                (snap_id, asset["name"], asset["type"], asset["value"], asset.get("invested", 0))
            )

    for d in data.get("asset_definitions", []):
        conn.execute(
            "INSERT INTO asset_definitions (name, type) VALUES (?, ?)",
            (d["name"], d["type"])
        )

    conn.commit()
    conn.close()
    return {"imported": len(data.get("snapshots", []))}

# ==================== STATIC FRONTEND ====================

app.mount("/", StaticFiles(directory="/frontend", html=True), name="frontend")