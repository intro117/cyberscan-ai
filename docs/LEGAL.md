# Alcance legal del escaneo

## Lo que este proyecto SI hace (reconocimiento pasivo / legal sobre cualquier dominio publico)

- Lectura de headers HTTP de una respuesta publica (equivalente a abrir el sitio en un navegador).
- Verificacion del certificado TLS que el propio servidor entrega a cualquier visitante.
- Consultas DNS publicas (A, TXT, SPF, DMARC, intentos de DKIM con selectores comunes).
- Consulta a Certificate Transparency logs (crt.sh) - informacion publica ya indexada por las
  Autoridades Certificadoras, no se toca la infraestructura del objetivo.

Todo esto es equivalente a lo que hacen herramientas publicas como securityheaders.com,
Mozilla Observatory o SSL Labs sobre cualquier dominio, sin necesitar autorizacion explicita,
porque no se envia trafico que exceda lo que cualquier navegador enviaria.

## Lo que este proyecto NO hace y por que

Deliberadamente NO se implemento en este MVP:

- **Escaneo de puertos (Nmap) o vulnerabilidades (OpenVAS) contra el objetivo.** Enviar paquetes
  disenados para enumerar puertos o explotar servicios de un sistema que no es tuyo, sin
  autorizacion por escrito, constituye acceso no autorizado a sistemas informaticos en la mayoria
  de jurisdicciones (en Mexico: Codigo Penal Federal, articulo 211 Bis 1; en EE.UU.: Computer Fraud
  and Abuse Act). Esto aplica incluso si el motivo es "solo para reportar el score".
- **Consultas activas a Shodan/VirusTotal/AbuseIPDB sobre dominios de terceros sin su consentimiento.**
  Aunque estas APIs en si mismas son legales de usar, construir un producto que reporta la postura
  de seguridad de un tercero sin su autorizacion puede generar responsabilidad si el resultado se
  usa de forma daniña (ej. reconocimiento previo a un ataque). El codigo para estas integraciones
  esta preparado (ver app/config.py) pero debe activarse SOLO bajo un modelo donde el usuario
  escanea dominios que le pertenecen o esta autorizado a auditar (flujo de verificacion de
  propiedad de dominio, ej. registro TXT, es el estandar de la industria - ver seccion siguiente).

## Recomendacion para produccion

Antes de habilitar cualquier modulo activo (puertos, vulnerabilidades, OSINT profundo), implementa
verificacion de propiedad de dominio: el usuario debe demostrar control del dominio (registro TXT
unico, o archivo en `/.well-known/`) antes de que el sistema ejecute escaneos mas invasivos que
una simple lectura HTTP/DNS publica. Esto es el mismo modelo que usan Google Search Console,
Cloudflare y la mayoria de scanners SaaS legitimos.
