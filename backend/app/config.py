"""
Configuracion central. TODO valor sensible se lee de variables de entorno.
Los valores por defecto son EJEMPLOS NO VALIDOS - deben sustituirse en .env o en
el gestor de secretos del entorno de despliegue (AWS Secrets Manager, GitHub Secrets, etc).
"""
import os
from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # --- App ---
    app_name: str = "CyberScan AI"
    environment: str = os.getenv("ENVIRONMENT", "development")
    debug: bool = os.getenv("DEBUG", "true").lower() == "true"

    # --- Database (Postgres) ---
    # NOTA: el valor por defecto aqui NUNCA se usa en docker-compose (ahi la
    # password real viene de ${POSTGRES_PASSWORD} definida en tu .env de raiz,
    # ver .env.example). Este default solo aplica si corres el backend fuera
    # de Docker Compose sin definir DATABASE_URL explicitamente.
    database_url: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://cyberscan:REPLACE_ME_LOCAL_DB_PASSWORD@localhost:5432/cyberscan",
    )

    # --- Redis (cache / rate limiting) ---
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # --- RabbitMQ (colas de escaneo async) ---
    rabbitmq_url: str = os.getenv(
        "RABBITMQ_URL", "amqp://guest:guest@localhost:5672/"
    )

    # --- Auth0 ---
    auth0_domain: str = os.getenv("AUTH0_DOMAIN", "your-tenant.us.auth0.com")
    auth0_api_audience: str = os.getenv("AUTH0_API_AUDIENCE", "https://api.cyberscan.ai")
    auth0_client_id: str = os.getenv("AUTH0_CLIENT_ID", "REPLACE_ME_AUTH0_CLIENT_ID")
    auth0_client_secret: str = os.getenv("AUTH0_CLIENT_SECRET", "REPLACE_ME_AUTH0_CLIENT_SECRET")

    # --- Integraciones externas de threat intel (opcionales, requieren API key propia) ---
    virustotal_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "REPLACE_ME_VT_API_KEY")
    shodan_api_key: str = os.getenv("SHODAN_API_KEY", "REPLACE_ME_SHODAN_API_KEY")
    abuseipdb_api_key: str = os.getenv("ABUSEIPDB_API_KEY", "REPLACE_ME_ABUSEIPDB_API_KEY")
    # HIBP ya no se usa por defecto (su API dejo de tener tier gratuito en 2024).
    # Se deja el campo por si en el futuro hay presupuesto para reactivarlo -
    # ver app/scanners/email_breach.py para el modulo activo actual (XposedOrNot, gratuito).
    hibp_api_key: str = os.getenv("HIBP_API_KEY", "REPLACE_ME_HIBP_API_KEY")
    numverify_api_key: str = os.getenv("NUMVERIFY_API_KEY", "REPLACE_ME_NUMVERIFY_API_KEY")

    # --- S3 / almacenamiento de reportes PDF ---
    aws_region: str = os.getenv("AWS_REGION", "us-east-1")
    s3_bucket_reports: str = os.getenv("S3_BUCKET_REPORTS", "cyberscan-ai-reports")
    aws_access_key_id: str = os.getenv("AWS_ACCESS_KEY_ID", "REPLACE_ME")
    aws_secret_access_key: str = os.getenv("AWS_SECRET_ACCESS_KEY", "REPLACE_ME")

    # --- Rate limiting ---
    rate_limit_per_minute: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "10"))

    # --- CORS ---
    # NOTA TECNICA: este campo se lee como str plano, NO como list[str], porque
    # pydantic-settings intenta parsear campos list[...] como JSON al leer env vars,
    # y "http://a,http://b" no es JSON valido -> SettingsError en el arranque.
    allowed_origins_raw: str = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000")

    @property
    def allowed_origins(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins_raw.split(",") if o.strip()]

    class Config:
        env_file = ".env"


@lru_cache
def get_settings() -> Settings:
    return Settings()
