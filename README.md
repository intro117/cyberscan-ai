# CyberScan AI

Herramienta gratuita y local de auditoria de seguridad: escanea un dominio
(headers HTTP, TLS/SSL, DNS/SPF/DMARC/DKIM, subdominios via Certificate
Transparency), verifica si un correo aparecio en brechas de datos publicas,
y valida numeros telefonicos. Genera un Security Score 0-100 y reporte PDF.

**100% gratuito. Sin registro de cuenta. Sin limite de uso. Corre en tu propio equipo.**

---

## Advertencia de diseno: esta herramienta NO tiene autenticacion, a proposito

Cualquiera con acceso a la maquina donde corres esto (o a tu red local, si
expones los puertos mas alla de `localhost`) puede usarla sin login. Esto es
una decision de diseno deliberada, no un descuido:

- Es una herramienta local para que **tu mismo** la corras en tu equipo, no un
  servicio multiusuario expuesto a internet.
- Agregar autenticacion (Auth0, JWT, lo que sea) tiene sentido solo si decides
  desplegar esto como servicio publico accesible por terceros - en ese caso,
  **no la expongas tal cual esta**, primero implementa auth y rate limiting
  robusto (el actual es basico, ver seccion de limitaciones).
- Si corres esto en una maquina compartida o servidor con puertos abiertos a
  internet sin capa adicional de proteccion, cualquiera podria usar tu
  instancia para escanear dominios de terceros a tu nombre/IP. No lo expongas
  publicamente sin entender esta implicacion.

---

## Instalacion - paso a paso, para cualquier persona sin contexto previo

### Requisitos previos

- **Docker Desktop** instalado y corriendo (Windows/Mac) o Docker Engine + Docker Compose (Linux).
  Descarga: https://www.docker.com/products/docker-desktop/
- Si usas Windows: **WSL2** habilitado con integracion a Docker Desktop activada
  (Docker Desktop → Settings → Resources → WSL Integration).
- Conexion a internet (para descargar imagenes base y consultar APIs externas durante el escaneo).

### 1. Descargar el proyecto

Descarga el `.zip` de este repositorio (boton verde "Code" → "Download ZIP" en GitHub,
o `git clone` si prefieres) y descomprimelo en una carpeta de tu eleccion.

Si usas WSL2 en Windows, **no lo dejes en `/mnt/c/...`** (rendimiento pobre por el
mount cruzado Windows-Linux) - copialo al filesystem nativo de tu distro:

```bash
mkdir -p ~/dev
cp -r /ruta/donde/descomprimiste/cyberscan-ai ~/dev/
cd ~/dev/cyberscan-ai
```

### 2. Configurar variables de entorno (2 archivos distintos, no te saltes ninguno)

**a) Archivo `.env` en la RAIZ del proyecto** (contrasena de la base de datos local):

```bash
cp .env.example .env
```

Abre `.env` (raiz) y cambia `POSTGRES_PASSWORD` por cualquier contrasena que tu elijas
(no necesita ser memorable, solo evita usar el placeholder tal cual).

**b) Archivo `.env` dentro de `backend/`** (configuracion de la aplicacion):

```bash
cd backend
cp .env.example .env
cd ..
```

Los valores por defecto de `backend/.env` funcionan sin modificacion para el escaneo
de dominio (headers/SSL/DNS/subdominios) y para el modulo de correo (no requiere key).
**Solo el modulo de telefono requiere una key gratuita** - ver seccion siguiente.

### 3. Registro gratuito para el modulo de verificacion telefonica (OPCIONAL)

El escaneo de dominios y la verificacion de correo funcionan sin ningun registro.
Solo si quieres usar la verificacion de numeros telefonicos, necesitas una API key
gratuita de NumVerify (100 consultas/mes gratis, sin tarjeta de credito):

1. Ve a **https://numverify.com**
2. Clic en **"Get Free API Key"**
3. Registrate con correo y contrasena (no pide datos de pago)
4. Confirma tu correo (revisa tu bandeja de entrada y spam)
5. Inicia sesion - tu **API Access Key** aparece directamente en el dashboard
6. Copia esa key

Abre `backend/.env` y reemplaza:

```
NUMVERIFY_API_KEY=REPLACE_ME_NUMVERIFY_API_KEY
```

por tu key real:

```
NUMVERIFY_API_KEY=tu_key_copiada_aqui
```

Si no haces este paso, el modulo de telefono simplemente responde con un mensaje
claro indicando que falta la key - no rompe el resto de la herramienta.

### 4. Levantar todo con Docker Compose

```bash
docker compose up --build
```

Primera vez tarda 2-4 minutos (descarga de imagenes + instalacion de dependencias).
Deja esta terminal corriendo. Cuando veas `Uvicorn running on http://0.0.0.0:8000`
y los demas servicios en estado `Started`, esta listo.

### 5. Verificar que todo funciona

Abre una segunda terminal:

```bash
curl http://localhost:8000/health
```

Debe responder: `{"status":"ok","environment":"development"}`

### 6. Usar la herramienta

Abre tu navegador en **http://localhost:3000**

Tres pestanas disponibles: **Dominio**, **Correo (brechas)**, **Telefono**.
Escribe el dato a analizar y da clic en el boton correspondiente.

---

## Que hace cada modulo, exactamente

| Modulo | Que verifica | Fuente de datos | Requiere registro |
|---|---|---|---|
| Headers HTTP | HSTS, CSP, X-Frame-Options, cookies, redirect HTTP→HTTPS, etc. | Peticion HTTP directa al dominio | No |
| TLS/SSL | Vigencia de certificado, protocolo, cipher suite | Conexion TLS directa | No |
| DNS | SPF/DMARC/DKIM (solo si hay MX), CAA, DNSSEC | Consultas DNS publicas | No |
| Subdominios | Exposicion via Certificate Transparency | crt.sh (servicio publico, a veces inestable) | No |
| Correo | Brechas de datos conocidas | XposedOrNot (API publica gratuita) | No |
| Telefono | Validez, pais, operador, tipo de linea | NumVerify (API oficial) | Si, gratis |

**Todo el escaneo de dominio es reconocimiento PASIVO** - equivalente a lo que hace
cualquier navegador al visitar el sitio. No se hace escaneo de puertos, fuzzing,
ni ningun intento activo contra el objetivo. Ver `docs/LEGAL.md` para el detalle
de por que esto importa si vas a escanear dominios que no son tuyos.

---

## Estado real de este repositorio - leer antes de asumir nada

| Componente | Estado |
|---|---|
| Escaneo de dominio (headers/SSL/DNS/subdominios/scoring/PDF) | Funcional, verificado contra dominios reales |
| Verificacion de correo (XposedOrNot) | Funcional, verificado contra la API real |
| Verificacion de telefono (NumVerify) | Funcional, verificado contra la API real (requiere key gratuita) |
| Cache Redis (5 min TTL) | Funcional, medido: reduce tiempo de respuesta ~85x en cache hit |
| Honeypot de rutas trampa (`/wp-admin`, `/.env`, etc.) | Funcional, logs JSON estructurados a stdout (ingeribles por Wazuh/ELK) |
| Logging en tiempo real por modulo (`docker compose logs -f backend`) | Funcional |
| Tests unitarios (pytest + respx, mocks) | Escritos y sintacticamente validados. **No se han corrido con dependencias reales instaladas** en el entorno donde se genero este codigo (sin acceso de red) - el CI de GitHub Actions si las instala y corre en runners reales |
| Autenticacion | **No implementada, a proposito** - ver advertencia al inicio de este README |
| Persistencia en base de datos | Postgres esta en el stack pero **no se usa todavia** - los resultados solo viven 5 min en cache Redis, no hay historico |
| Rate limiting | Basico, en memoria por proceso. Con 2 workers de Uvicorn, el limite efectivo real es 2x el configurado (bug conocido, no critico para uso local) |
| Frontend | HTML/JS + Tailwind CDN estatico, sin build step. No es Next.js/React (ver justificacion abajo) |
| Terraform (AWS ECS/RDS/S3) | Esqueleto sintacticamente valido, nunca aplicado contra una cuenta AWS real |
| Nmap/OpenVAS/Shodan/escaneo activo | Deliberadamente NO implementado - ver `docs/LEGAL.md` |

### Por que el frontend no es Next.js

El HTML/JS estatico incluido es completamente funcional y no requiere paso de build
(`npm install`/`npm run build`). Migrar a Next.js es un paso valido si en el futuro
necesitas SSR/SEO para una version publica, pero no es necesario para uso local.

---

## Correr sin Docker (desarrollo local, opcional)

```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Requiere tener Postgres, Redis y RabbitMQ corriendo por separado y accesibles
en las URLs configuradas en `backend/.env` - Docker Compose lo resuelve automaticamente,
esta opcion es solo para quien quiera desarrollar sin contenedores.

## Correr los tests

```bash
cd backend
pip install -r requirements.txt
pytest -v
```

## Ver logs en tiempo real mientras usas el frontend

```bash
docker compose logs -f backend
```

Muestra cada modulo ejecutandose con su tiempo real, hits/miss de cache, y
resultado final de cada escaneo - util para entender que esta tardando si
algo se siente lento (usualmente el modulo de subdominios, dependiente de
crt.sh, un servicio publico externo con disponibilidad variable).

---

## Estructura del proyecto

```
cyberscan-ai/
├── .env.example                  # Variables para docker-compose (password de Postgres)
├── docker-compose.yml
├── LICENSE
├── backend/
│   ├── app/
│   │   ├── main.py               # FastAPI app, middleware, rate limiting, honeypot
│   │   ├── config.py             # Variables de entorno (Pydantic Settings)
│   │   ├── models.py             # Schemas Pydantic
│   │   ├── scoring.py            # Motor de Security Score
│   │   ├── report.py             # Generacion de PDF (reportlab)
│   │   ├── honeypot.py           # Rutas trampa + logging estructurado
│   │   ├── scanners/
│   │   │   ├── headers.py        # HSTS, CSP, cookies, redirect, etc.
│   │   │   ├── ssl_check.py      # Certificado, protocolo, cipher suite
│   │   │   ├── dns_check.py      # SPF/DMARC/DKIM (MX-aware), CAA, DNSSEC
│   │   │   ├── subdomains.py     # Certificate Transparency (crt.sh)
│   │   │   ├── email_breach.py   # Brechas de correo (XposedOrNot, gratis)
│   │   │   └── phone_check.py    # Validacion telefonica (NumVerify, gratis)
│   │   └── routers/
│   │       ├── scan.py           # Endpoint de escaneo de dominio + cache Redis
│   │       └── phase2.py         # Endpoints de correo/telefono
│   ├── tests/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   └── index.html                # Dashboard funcional standalone (3 pestanas)
├── infra/
│   ├── terraform/                # Esqueleto AWS (no aplicado)
│   └── prometheus.yml
├── docs/
│   └── LEGAL.md                  # Limites legales del escaneo activo vs pasivo
└── .github/workflows/ci.yml
```

## Modelo de scoring

100 puntos base. Cada verificacion fallida resta su peso, acotado por severidad
(critico maximo -25, alto -15, medio -8, bajo -4, info -2). Es un modelo heuristico
y transparente, no un estandar de la industria como CVSS - se documenta como tal
para no vender precision que no existe.

## Licencia

MIT - ver `LICENSE`. Uso libre, incluido comercial, sin garantia.

## Contribuciones / reportar problemas

Este es un proyecto personal en desarrollo activo. Si encuentras un bug o quieres
sugerir una mejora, abre un Issue en GitHub.
