from datetime import datetime, timezone
import logging
import sys
import time

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
import io
import redis.asyncio as aioredis

from app.config import get_settings
from app.models import ScanRequest, ScanResult, Finding, Severity
from app.scoring import compute_score
from app.report import build_pdf_report
from app.scanners import headers as headers_scanner
from app.scanners import ssl_check
from app.scanners import dns_check
from app.scanners import subdomains as subdomains_scanner

router = APIRouter(prefix="/api/v1/scan", tags=["scan"])
settings = get_settings()

# --- Logger dedicado para progreso de escaneo en tiempo real ---
# Formato de una sola linea con timestamp legible, pensado para `docker compose
# logs -f backend` mientras el usuario dispara escaneos desde el frontend.
scan_logger = logging.getLogger("cyberscan.scan")
scan_logger.setLevel(logging.INFO)
_scan_handler = logging.StreamHandler(sys.stdout)
_scan_handler.setFormatter(logging.Formatter("[SCAN] %(asctime)s | %(message)s", datefmt="%H:%M:%S"))
scan_logger.addHandler(_scan_handler)
scan_logger.propagate = False

MODULES = {
    "headers": headers_scanner.scan_headers,
    "ssl": ssl_check.scan_ssl,
    "dns": dns_check.scan_dns,
    "subdomains": subdomains_scanner.scan_subdomains,
}

CACHE_TTL_SECONDS = 300  # 5 min: evita re-escanear el mismo dominio en rafaga y reduce carga a crt.sh/DNS
_redis_client: aioredis.Redis | None = None


async def _get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
    return _redis_client


@router.post("", response_model=ScanResult)
async def run_scan(payload: ScanRequest) -> ScanResult:
    domain = payload.domain
    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Dominio invalido.")

    t_start = time.monotonic()
    scan_logger.info(f"===== INICIO escaneo: {domain} =====")

    cache_key = f"cyberscan:result:{domain}"
    try:
        redis_client = await _get_redis()
        cached = await redis_client.get(cache_key)
        if cached:
            elapsed = time.monotonic() - t_start
            scan_logger.info(f"CACHE HIT para {domain} ({elapsed*1000:.0f}ms) - resultado servido desde Redis, sin re-escanear")
            return ScanResult.model_validate_json(cached)
        scan_logger.info(f"CACHE MISS para {domain} - procediendo a escaneo completo")
    except Exception as exc:
        redis_client = None
        scan_logger.info(f"Redis no disponible ({exc}) - continuando sin cache")

    all_findings: list[Finding] = []
    modules_run: list[str] = []
    modules_failed: list[str] = []

    for name, fn in MODULES.items():
        t_module = time.monotonic()
        scan_logger.info(f"  -> Ejecutando modulo '{name}'...")
        try:
            findings = await fn(domain)
            elapsed_module = time.monotonic() - t_module
            failed_count = sum(1 for f in findings if not f.passed)
            scan_logger.info(
                f"  <- Modulo '{name}' completado en {elapsed_module:.2f}s "
                f"({len(findings)} checks, {failed_count} fallidos)"
            )
            all_findings.extend(findings)
            modules_run.append(name)
        except Exception as exc:  # noqa: BLE001 - degradacion controlada, no debe tumbar el scan completo
            elapsed_module = time.monotonic() - t_module
            scan_logger.info(f"  !! Modulo '{name}' FALLO tras {elapsed_module:.2f}s: {exc}")
            modules_failed.append(name)
            all_findings.append(Finding(
                module=name, check="module_execution", severity=Severity.INFO,
                passed=False, detail=f"El modulo '{name}' fallo durante la ejecucion: {exc}",
                weight=0,
            ))

    score, grade = compute_score(all_findings)

    result = ScanResult(
        domain=domain,
        scanned_at=datetime.now(timezone.utc),
        score=score,
        grade=grade,
        findings=all_findings,
        modules_run=modules_run,
        modules_failed=modules_failed,
    )

    if redis_client is not None:
        try:
            await redis_client.set(cache_key, result.model_dump_json(), ex=CACHE_TTL_SECONDS)
            scan_logger.info(f"Resultado cacheado en Redis (TTL {CACHE_TTL_SECONDS}s)")
        except Exception as exc:
            scan_logger.info(f"No se pudo cachear en Redis: {exc}")

    total_elapsed = time.monotonic() - t_start
    scan_logger.info(
        f"===== FIN escaneo: {domain} | score={score} grado={grade} | "
        f"tiempo total={total_elapsed:.2f}s | modulos_fallidos={modules_failed or 'ninguno'} ====="
    )

    return result


@router.get("/{domain}/report.pdf")
async def download_report(domain: str):
    # NOTA: se lee de Redis, NO de un dict en memoria del proceso. Uvicorn corre
    # con --workers 2 (ver Dockerfile); un dict en memoria es por-worker y el
    # request de descarga del PDF puede caer en un worker distinto al que hizo
    # el escaneo, causando un 404 intermitente e imposible de reproducir de forma
    # consistente. Redis es compartido entre workers y evita ese bug de raiz.
    try:
        redis_client = await _get_redis()
        cached = await redis_client.get(f"cyberscan:result:{domain}")
    except Exception:
        cached = None

    if not cached:
        raise HTTPException(
            status_code=404,
            detail="No hay un escaneo reciente (ultimos 5 min) para este dominio, o Redis no esta disponible. "
                   "Ejecuta POST /api/v1/scan primero.",
        )

    result = ScanResult.model_validate_json(cached)
    pdf_bytes = build_pdf_report(result)
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=cyberscan-{domain}.pdf"},
    )
