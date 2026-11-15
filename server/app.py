"""Aplikasi FastAPI: WebSocket /ws, REST /api/*, dan berkas statis dashboard."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .config import Config, ConfigError
from .db import Database
from .engine import Engine
from .sources import LineSource

log = logging.getLogger("conda.app")

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DEFAULT_DB = os.path.join(ROOT, "data", "conda.db")


class PromoteBody(BaseModel):
    bssid: str
    ssid: Optional[str] = None
    security: Optional[List[str]] = None


class IgnoreBody(BaseModel):
    bssid: str


def create_app(cfg_dir: Optional[str] = None, db_path: str = DEFAULT_DB,
               source: Optional[LineSource] = None, record_path: Optional[str] = None,
               fresh: bool = False) -> FastAPI:
    cfg = Config(cfg_dir)
    if fresh and db_path != ":memory:" and os.path.exists(db_path):
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(db_path + suffix):
                os.unlink(db_path + suffix)
    if db_path != ":memory:":
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
    db = Database(db_path)
    clients: set = set()
    state: Dict[str, Any] = {"recorder": None, "t0": 0.0}

    def send_cmd(cmd: dict) -> None:
        if source is not None:
            source.write(cmd)

    engine = Engine(cfg, db, send_cmd=send_cmd)

    async def broadcast(ev: Dict[str, Any]) -> None:
        rec = state["recorder"]
        if rec is not None:                      # rekaman untuk mode replay (docs/protokol.md §7)
            rec.write(json.dumps(dict(ev, at=round(time.monotonic() - state["t0"], 3)), ensure_ascii=False) + "\n")
            rec.flush()
        for ws in list(clients):
            try:
                await ws.send_json(ev)
            except Exception:
                clients.discard(ws)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()

        def push(line: str) -> None:             # aman dipanggil dari thread mana pun
            loop.call_soon_threadsafe(queue.put_nowait, line)

        app.state.push = push

        async def consumer():
            while True:
                line = await queue.get()
                for ev in engine.handle_line(line):
                    await broadcast(ev)

        async def ticker():
            interval = cfg.thresholds["node_check_interval_s"]
            while True:
                await asyncio.sleep(interval)
                for ev in engine.tick():
                    await broadcast(ev)

        if record_path:
            os.makedirs(os.path.dirname(os.path.abspath(record_path)), exist_ok=True)
            state["recorder"] = open(record_path, "w", encoding="utf-8")
            state["t0"] = time.monotonic()
            await broadcast(engine.snapshot())   # baris pertama rekaman = keadaan awal
        tasks = [asyncio.create_task(consumer()), asyncio.create_task(ticker())]
        if source is not None:
            source.start(push)
            log.info("sumber data: %s", source.name)
        else:
            log.warning("tidak ada sumber data (--serial/--sim/--stdin); hanya API yang aktif")
        try:
            yield
        finally:
            for t in tasks:
                t.cancel()
            if source is not None:
                source.stop()
            if state["recorder"]:
                state["recorder"].close()
            db.close()

    app = FastAPI(title="CONDA", version="1.0", lifespan=lifespan)
    app.state.engine = engine
    app.state.cfg = cfg

    # ----------------------------------------------------------- WebSocket
    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket):
        await ws.accept()
        await ws.send_json(engine.snapshot())
        clients.add(ws)
        try:
            while True:
                await ws.receive_text()          # dashboard tidak mengirim apa pun; hanya menjaga koneksi
        except WebSocketDisconnect:
            pass
        finally:
            clients.discard(ws)

    # ---------------------------------------------------------------- REST
    @app.get("/api/state")
    async def api_state():
        return engine.snapshot()

    @app.get("/api/alerts")
    async def api_alerts(limit: int = Query(100, ge=1, le=1000)):
        return db.recent_alerts(limit)

    @app.get("/api/health")
    async def api_health():
        return {"ok": True, "source": source.name if source else None, "clients": len(clients),
                "stats": engine.stats, "nodes": {n: v["state"] for n, v in engine.nodes.items()}}

    @app.post("/api/whitelist/promote")
    async def api_promote(body: PromoteBody):
        try:
            events = engine.promote(body.bssid, body.ssid, body.security)
        except (ValueError, ConfigError) as e:
            raise HTTPException(400, str(e))
        for ev in events:
            await broadcast(ev)
        return {"ok": True}

    @app.post("/api/whitelist/ignore")
    async def api_ignore(body: IgnoreBody):
        try:
            events = engine.ignore(body.bssid)
        except (ValueError, ConfigError) as e:
            raise HTTPException(400, str(e))
        for ev in events:
            await broadcast(ev)
        return {"ok": True}

    @app.post("/api/alerts/{alert_id}/ack")
    async def api_ack(alert_id: int):
        if not engine.ack(alert_id):
            raise HTTPException(404, "alert tidak ditemukan")
        await broadcast({"t": "alert_ack", "id": alert_id})
        return {"ok": True}

    @app.post("/api/alarm/clear")
    async def api_clear():
        for ev in engine.clear_alarms():
            await broadcast(ev)
        return {"ok": True}

    # ------------------------------------------------- berkas statis (terakhir)
    samples = os.path.join(ROOT, "data", "samples")
    dash = os.path.join(ROOT, "dashboard")
    if os.path.isdir(samples):
        app.mount("/samples", StaticFiles(directory=samples), name="samples")
    if os.path.isdir(dash):
        app.mount("/", StaticFiles(directory=dash, html=True), name="dashboard")
    return app
