"""
Honeypot ligero: rutas trampa comunmente sondeadas por bots/scanners automatizados
(wp-admin, .env, phpmyadmin, etc). Cualquier hit se loguea en JSON estructurado a
stdout - el driver de logging de Docker lo captura, y desde ahi un Filebeat/Wazuh
agent o Logstash lo puede ingestar sin tocar el filesystem del contenedor (que es
efimero). Esto es dogfooding directo del stack que ya operas (Wazuh + Elasticsearch).

Deliberadamente responde 404 generico (no un "has sido detectado, eres un honeypot")
para no revelar al atacante que su sondeo fue registrado.
"""
from __future__ import annotations

import json
import logging
import sys
import time

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

honeypot_logger = logging.getLogger("cyberscan.honeypot")
honeypot_logger.setLevel(logging.INFO)
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("%(message)s"))
honeypot_logger.addHandler(_handler)
honeypot_logger.propagate = False

router = APIRouter(tags=["honeypot"], include_in_schema=False)

TRAP_PATHS = [
    "/wp-admin", "/wp-login.php", "/.env", "/.env.local", "/.git/config",
    "/phpmyadmin", "/admin", "/administrator", "/xmlrpc.php", "/config.php",
    "/.aws/credentials", "/actuator/env", "/server-status", "/.well-known/traversal-test",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
]


def _log_trap_hit(request: Request, path: str) -> None:
    event = {
        "event_type": "honeypot_trap_hit",
        "timestamp": time.time(),
        "source_ip": request.client.host if request.client else "unknown",
        "path": path,
        "method": request.method,
        "user_agent": request.headers.get("user-agent", ""),
        "referer": request.headers.get("referer", ""),
        "headers_count": len(request.headers),
    }
    # JSON en una sola linea: formato ingerible directo por Filebeat/Wazuh sin parser custom
    honeypot_logger.info(json.dumps(event, ensure_ascii=False))


def register_honeypot_routes(app) -> None:
    """Registra dinamicamente las rutas trampa sobre la app FastAPI."""
    for trap_path in TRAP_PATHS:
        async def _trap_handler(request: Request, _path=trap_path):
            _log_trap_hit(request, _path)
            return JSONResponse(status_code=404, content={"detail": "Not Found"})

        app.add_api_route(
            trap_path, _trap_handler, methods=["GET", "POST"], include_in_schema=False,
        )
