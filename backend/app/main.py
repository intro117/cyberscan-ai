from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import time
from collections import defaultdict, deque

from prometheus_fastapi_instrumentator import Instrumentator

from app.config import get_settings
from app.routers import scan, phase2
from app.honeypot import register_honeypot_routes

settings = get_settings()

# En produccion (despliegue publico), se desactiva Swagger UI/ReDoc/OpenAPI schema.
# No es una vulnerabilidad critica per se, pero regala gratis la estructura completa
# de la API (endpoints, parametros, modelos) a cualquiera que la visite - informacion
# de reconocimiento que no tiene motivo de estar publica en una instancia expuesta.
# En local (development) se mantiene activo por conveniencia de desarrollo.
_is_production = settings.environment == "production"

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="API de CyberScan AI - escaneo pasivo de postura de seguridad de un dominio.",
    docs_url=None if _is_production else "/docs",
    redoc_url=None if _is_production else "/redoc",
    openapi_url=None if _is_production else "/openapi.json",
)

Instrumentator().instrument(app).expose(app, endpoint="/metrics")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# --- Rate limiting simple en memoria por IP (produccion: mover a Redis + slowapi) ---
class SimpleRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limit_per_minute: int):
        super().__init__(app)
        self.limit = limit_per_minute
        self.hits: dict[str, deque] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        ip = request.client.host if request.client else "unknown"
        now = time.time()
        window = self.hits[ip]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= self.limit:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit excedido. Intenta de nuevo en un minuto."},
            )
        window.append(now)
        return await call_next(request)


app.add_middleware(SimpleRateLimitMiddleware, limit_per_minute=settings.rate_limit_per_minute)


# --- Security headers en las respuestas de la propia API (dogfooding) ---
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.get("/health")
async def health():
    return {"status": "ok", "environment": settings.environment}


app.include_router(scan.router)
app.include_router(phase2.router)
register_honeypot_routes(app)
