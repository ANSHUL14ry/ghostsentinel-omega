"""
GHOSTSENTINEL Ω — Main FastAPI Application Entry Point

Security hardening:
- Binds to 127.0.0.1 by default (no public internet exposure)
- CORS restricted to localhost
- Global exception handlers
- Structured logging with redaction
"""
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.core.logging_config import get_logger
from app.database import init_db

# API routers
from app.api.wifi import router as wifi_router
from app.api.devices import router as devices_router
from app.api.password import router as password_router
from app.api.findings import router as findings_router, reports_router
from app.api.system import router as system_router
from app.api.baseline import router as baseline_router
from app.api.lab import router as lab_router

logger = get_logger(__name__)

BASE_DIR = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("GHOSTSENTINEL Ω starting up…")
    init_db()
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    yield
    logger.info("GHOSTSENTINEL Ω shutting down.")


app = FastAPI(
    title="GHOSTSENTINEL Ω",
    description=(
        "Wi-Fi Security & Privacy Auditing Platform. "
        "Use only on networks you are authorised to test."
    ),
    version=settings.app_version,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

# ── Security: CORS restricted to localhost ────────────────────────────────────
allowed_origins = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    f"http://localhost:{settings.port}",
    f"http://127.0.0.1:{settings.port}",
]
if settings.allow_lan_access:
    logger.warning("LAN access is ENABLED — ensure firewall rules are configured.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "Accept"],
)

# ── Exception handlers ────────────────────────────────────────────────────────
register_exception_handlers(app)

# ── API routes ────────────────────────────────────────────────────────────────
app.include_router(wifi_router)
app.include_router(devices_router)
app.include_router(password_router)
app.include_router(findings_router)
app.include_router(reports_router)
app.include_router(system_router)
app.include_router(baseline_router)
app.include_router(lab_router)

# ── Static files (CSS, JS, images) ────────────────────────────────────────────
static_dir = BASE_DIR / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


# ── SPA fallback — serve dashboard for any non-API route ─────────────────────
NO_CACHE_HEADERS = {
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}


@app.get("/", include_in_schema=False)
async def root():
    return FileResponse(
        str(BASE_DIR / "templates" / "index.html"),
        headers=NO_CACHE_HEADERS,
    )


@app.get("/{full_path:path}", include_in_schema=False)
async def spa_fallback(full_path: str):
    # Don't intercept API or static routes
    if full_path.startswith("api/") or full_path.startswith("static/"):
        from fastapi import HTTPException
        raise HTTPException(status_code=404)
    index = BASE_DIR / "templates" / "index.html"
    if index.exists():
        return FileResponse(str(index), headers=NO_CACHE_HEADERS)
    from fastapi import HTTPException
    raise HTTPException(status_code=404, detail="Frontend not found.")
