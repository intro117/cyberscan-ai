# Despliegue QA gratuito — Upstash + Render + Vercel

Guia paso a paso para levantar CyberScan AI en internet, 100% gratis, sin
tarjeta de credito, usando el repositorio que ya esta en GitHub.

## Analisis previo (leer antes de empezar)

- **Postgres y RabbitMQ NO se usan** en ninguna parte funcional del codigo
  actual (confirmado por auditoria de codigo) - se omiten en este despliegue.
  Si en el futuro se implementa persistencia real de historico de escaneos,
  ahi se justificaria anadir Supabase (Postgres gratuito). No antes.
- **Redis SI es funcional** (cache de 5 min, medido con mejora de ~85x en
  tiempo de respuesta) - se reemplaza por Upstash (Redis serverless gratuito).
- **Render free tier "duerme" el servicio tras 15 min sin trafico.** El primer
  request tras inactividad tarda 30-50s en responder (cold start). Si vas a
  hacer una demo en vivo, manda un request de "calentamiento" 1-2 minutos antes.
- Algunos pasos requieren navegador (crear cuenta/login OAuth en cada
  plataforma) - no hay forma de evitar esto en servicios gratuitos de terceros.
  Se marca explicitamente cada paso que requiere navegador vs. terminal.

---

## Paso 1 — Upstash (Redis gratuito) — REQUIERE NAVEGADOR

1. Ve a **https://upstash.com** → "Sign Up" (puedes usar tu cuenta de GitHub)
2. Dashboard → **"Create Database"**
3. Nombre: `cyberscan-redis`, tipo: **Regional** (no Global, no lo necesitas)
4. Region: la mas cercana a Render (recomendado: `us-east-1` si vas a
   desplegar Render en Oregon/US, que es la region por defecto del free tier)
5. Clic en **"Create"**
6. En el dashboard de la base creada, busca la seccion **"REST API"** o
   **"Connect"** → copia el valor de **"Redis URL"** (empieza con `rediss://`)
7. Guarda ese valor, lo necesitas en el Paso 2

---

## Paso 2 — Render (backend) — REQUIERE NAVEGADOR para conectar el repo

1. Ve a **https://render.com** → "Get Started" → conecta tu cuenta de GitHub
2. Dashboard → **"New +"** → **"Blueprint"**
3. Selecciona el repositorio **intro117/cyberscan-ai** (ya esta en GitHub)
4. Render detecta automaticamente el archivo `render.yaml` de la raiz y
   preconfigura el servicio `cyberscan-ai-backend`
5. Te va a pedir que rellenes manualmente las variables marcadas `sync: false`:
   - `REDIS_URL`: pega el valor de Upstash del Paso 1
   - `ALLOWED_ORIGINS`: por ahora deja `http://localhost:3000` (lo actualizas
     en el Paso 4, despues de tener la URL real de Vercel)
   - `NUMVERIFY_API_KEY`: opcional, pega tu key gratuita si ya la tienes
6. Clic en **"Apply"** / **"Create Web Service"**
7. Espera 3-5 minutos al primer build. Cuando termine, copia la URL publica
   que Render te asigna (formato `https://cyberscan-ai-backend-XXXX.onrender.com`)

### Verificar desde tu WSL2 (esto SI es copiar y pegar)

```bash
curl -sw "\nHTTP_STATUS:%{http_code}\n" https://TU-URL-DE-RENDER.onrender.com/health
```

Debe responder `{"status":"ok","environment":"production"}` con `HTTP_STATUS:200`.
Si tarda 30-50s en la primera llamada, es el cold start esperado del free tier,
no un error.

---

## Paso 3 — Actualizar el frontend con la URL real de Render (esto SI es WSL2)

```bash
cd ~/dev/cyberscan-ai
sed -i 's|REPLACE_ME_RENDER_URL|https://TU-URL-DE-RENDER.onrender.com|' frontend/index.html
grep "RENDER_BACKEND_URL" frontend/index.html
```

El `grep` debe mostrar tu URL real de Render, no el placeholder.

---

## Paso 4 — Vercel (frontend) — login requiere navegador UNA vez, el resto es CLI

```bash
npm install -g vercel
cd ~/dev/cyberscan-ai/frontend
vercel login
```

Esto abre un link para autenticarte en el navegador (una sola vez). Despues:

```bash
vercel --prod
```

Te va a preguntar configuracion basica (nombre de proyecto, directorio - acepta
los defaults ya que `frontend/` es un sitio estatico simple, sin build step).
Al terminar, Vercel te da una URL publica (formato
`https://cyberscan-ai-xxxx.vercel.app`).

---

## Paso 5 — Cerrar el circulo: actualizar ALLOWED_ORIGINS en Render

Vuelve al dashboard de Render (navegador) → tu servicio → **"Environment"** →
edita `ALLOWED_ORIGINS` con tu URL real de Vercel (sin slash final):

```
https://cyberscan-ai-xxxx.vercel.app
```

Guarda - Render redeploya automaticamente (1-2 min).

---

## Paso 6 — Verificacion end-to-end (WSL2)

```bash
echo "=== Calentando el backend (evita cold start durante la prueba) ==="
curl -s https://TU-URL-DE-RENDER.onrender.com/health > /dev/null
sleep 3

echo "=== Probando escaneo real a traves del stack en la nube ==="
curl -sX POST https://TU-URL-DE-RENDER.onrender.com/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}' -o /tmp/qa_scan.json -w "HTTP_STATUS:%{http_code}\n"
cat /tmp/qa_scan.json | python3 -m json.tool

echo "=== Confirmando que el frontend en Vercel carga ==="
curl -sw "\nHTTP_STATUS:%{http_code}\n" https://TU-URL-VERCEL.vercel.app -o /dev/null
```

Abre `https://TU-URL-VERCEL.vercel.app` en el navegador, corre un escaneo desde
la UI, y confirma que no hay errores de CORS en la consola (F12 → Console).

---

## Limitaciones conocidas de este despliegue QA (honestas, no ocultas)

- Free tier de Render duerme tras 15 min sin trafico (cold start ~30-50s)
- Free tier de Upstash tiene limite de comandos/mes (revisar dashboard de
  Upstash para el limite vigente de tu cuenta)
- Sin dominio propio - usas los subdominios gratuitos de Render/Vercel
- Sin HTTPS personalizado mas alla del que Render/Vercel proveen por defecto
  (que ya es HTTPS valido, solo no es tu dominio propio)
- Esto es un entorno de **QA/demo**, no una arquitectura validada para
  trafico de produccion real o escala
