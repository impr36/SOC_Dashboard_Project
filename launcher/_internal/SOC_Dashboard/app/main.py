from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi import WebSocket

from app.api.rules_api      import router as rules_router
from app.api.dashboard_api  import router as dashboard_router
from app.api.auth_api       import router as auth_router

from app.rules.load_default_rules import load_default_rules
from app.services.realtime_monitor import RealtimeMonitor
from app.services.soc_service import soc_service
from app.websocket_manager import manager
from app.api.settings_api   import router as settings_router

# =========================================
# BASE DIRECTORY
# =========================================

BASE_DIR = Path(__file__).resolve().parent
monitor  = RealtimeMonitor()

# =========================================
# LIFESPAN
# =========================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    soc_service.reset_live_dashboard()
    print("[SOC] Live dashboard reset")
    print("[SOC] Dashboard session initialized")
    yield


# =========================================
# FASTAPI APP
# =========================================

app = FastAPI(lifespan=lifespan)

# =========================================
# STATIC FILES
# =========================================

app.mount(
    "/static",
    StaticFiles(directory=str(BASE_DIR / "static")),
    name="static"
)

# =========================================
# TEMPLATES
# =========================================

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# =========================================
# ROUTERS
# =========================================

app.include_router(auth_router)
app.include_router(rules_router)
app.include_router(dashboard_router)
app.include_router(settings_router)

# =========================================
# LOAD DEFAULT DETECTION RULES
# =========================================

load_default_rules()

# =========================================
# WEBSOCKET
# =========================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except Exception:
        manager.disconnect(websocket)


# =========================================
# ROOT — redirect to dashboard
# (actual auth check happens client-side on
# dashboard load; /api/auth/validate is the
# server-side gate)
# =========================================

@app.get("/")
async def root():
    return RedirectResponse(url="/dashboard")


# =========================================
# DASHBOARD PAGE
# Token validation happens in the browser:
# dashboard.html loads login.js which calls
# /api/auth/validate before showing any content.
# =========================================

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html"
    )