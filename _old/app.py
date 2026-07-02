"""nym maestro — local orchestrator.

Runs on your Mac. Serves the dashboard and owns the node registry. Connects out
to node agents over mTLS (added in slice 2). Bind to localhost only.

    pip install -r requirements.txt
    python app.py                 # http://127.0.0.1:7766
    python app.py --addr 127.0.0.1:7766 --db ~/.nym-maestro/maestro.db
"""
import argparse
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

from store import Conflict, Store

VERSION = "0.1.0"
BASE = Path(__file__).resolve().parent
INDEX_HTML = (BASE / "web" / "index.html").read_bytes()
SCHEMA = (BASE / "schema.sql").read_text()


def default_db() -> str:
    return os.environ.get("MAESTRO_DB") or str(
        Path.home() / ".nym-maestro" / "maestro.db"
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    db = default_db()
    Path(db).parent.mkdir(parents=True, exist_ok=True)
    app.state.store = Store(db, SCHEMA)
    yield
    app.state.store.close()


app = FastAPI(title="nym maestro", version=VERSION, lifespan=lifespan)


# Keep the API's error shape as {"error": "..."} so the UI stays unchanged.
@app.exception_handler(HTTPException)
async def _http_exc(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})


@app.exception_handler(RequestValidationError)
async def _validation_exc(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=400, content={"error": "invalid request body"})


class NodeCreate(BaseModel):
    node_id: str
    name: str
    ip: str
    hostname: str = ""
    agent_port: int = 8443
    agent_fp: str = ""
    service_name: str = ""
    binary_path: str = ""
    notes: str = ""
    enabled: bool = True


class NodePatch(BaseModel):
    name: str | None = None
    ip: str | None = None
    hostname: str | None = None
    agent_port: int | None = None
    agent_fp: str | None = None
    service_name: str | None = None
    binary_path: str | None = None
    notes: str | None = None
    enabled: bool | None = None


@app.get("/", response_class=HTMLResponse)
def index():
    return HTMLResponse(INDEX_HTML)


@app.get("/api/health")
def health():
    return {"status": "ok", "version": VERSION}


@app.get("/api/nodes")
def list_nodes(request: Request):
    return request.app.state.store.list_nodes()


@app.get("/api/nodes/{node_id}")
def get_node(node_id: str, request: Request):
    v = request.app.state.store.get_node(node_id)
    if v is None:
        raise HTTPException(404, "no node with that id")
    return v


@app.post("/api/nodes", status_code=201)
def create_node(n: NodeCreate, request: Request):
    node_id, name, ip = n.node_id.strip(), n.name.strip(), n.ip.strip()
    if not (node_id and name and ip):
        raise HTTPException(400, "node_id, name and ip are required")
    data = n.model_dump()
    data.update(
        node_id=node_id, name=name, ip=ip,
        hostname=n.hostname.strip(), notes=n.notes.strip(),
        service_name=n.service_name.strip(), binary_path=n.binary_path.strip(),
        agent_fp=n.agent_fp.strip(),
    )
    try:
        request.app.state.store.create_node(data)
    except Conflict as e:
        raise HTTPException(409, str(e))
    return request.app.state.store.get_node(node_id)


@app.patch("/api/nodes/{node_id}")
def update_node(node_id: str, patch: NodePatch, request: Request):
    fields = patch.model_dump(exclude_unset=True)
    for k in ("hostname", "agent_fp", "service_name", "binary_path", "notes"):
        if k in fields and isinstance(fields[k], str):
            fields[k] = fields[k].strip() or None
    for k in ("name", "ip"):
        if k in fields and isinstance(fields[k], str):
            fields[k] = fields[k].strip()
    try:
        ok = request.app.state.store.update_node(node_id, fields)
    except Conflict as e:
        raise HTTPException(409, str(e))
    if not ok:
        raise HTTPException(404, "no node with that id")
    return request.app.state.store.get_node(node_id)


@app.delete("/api/nodes/{node_id}", status_code=204)
def delete_node(node_id: str, request: Request):
    if not request.app.state.store.delete_node(node_id):
        raise HTTPException(404, "no node with that id")
    return Response(status_code=204)


def main():
    ap = argparse.ArgumentParser(prog="nym-maestro")
    ap.add_argument("--addr", default="127.0.0.1:7766", help="listen address (keep on localhost)")
    ap.add_argument("--db", default=default_db(), help="path to the SQLite database")
    args = ap.parse_args()
    os.environ["MAESTRO_DB"] = args.db
    host, _, port = args.addr.rpartition(":")

    import uvicorn
    uvicorn.run(app, host=host or "127.0.0.1", port=int(port))


if __name__ == "__main__":
    main()
