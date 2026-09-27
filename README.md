# Vuln Portal — Repositorio vulnerable (Laboratorio 04, EX-04)

Aplicación **deliberadamente vulnerable** (Flask / Python) creada para la fase
DevSecOps del Laboratorio 04. Su único propósito es que una herramienta SAST
(**Snyk** o **SonarCloud**) detecte los fallos plantados y luego se corrijan en
la fase EX-05.

> ⚠️ **No desplegar en producción.** Este código contiene vulnerabilidades a
> propósito y no debe ejecutarse en una red real.

- **Asignatura:** Fundamentos de seguridad de la información
- **Integrantes:** Daniel José Villamizar Castellanos · Gina Sofía García Zapata
- **Grupo:** 1L

## Fallos plantados (estado "before" — tag `v0-vulnerable`)

Cada fallo está marcado en el código con un comentario `# [VULN-0x]`.

| ID | Vulnerabilidad | Archivo:línea | CWE | OWASP Top 10 |
|----|----------------|---------------|-----|--------------|
| VULN-01 | Inyección SQL (consulta por concatenación de strings) | `app.py:62` | CWE-89 | A03:2021 – Injection |
| VULN-02 | Inyección de comandos (`os.popen` con entrada del usuario) | `app.py:86` | CWE-78 | A03:2021 – Injection |
| VULN-03 | Secretos embebidos (`secret_key` y API key hardcodeadas) | `app.py:19`, `app.py:20` | CWE-798 | A07:2021 – Identification & Auth Failures |
| VULN-04 | Hashing débil de contraseñas (MD5 sin sal) | `app.py:38`, `app.py:58` | CWE-327 | A02:2021 – Cryptographic Failures |
| VULN-05 | Path traversal en `/download` | `app.py:95` | CWE-22 | A01:2021 – Broken Access Control |
| VULN-06 | Deserialización insegura (`yaml.load` sin `SafeLoader`) | `app.py:105` | CWE-502 | A08:2021 – Software & Data Integrity Failures |
| VULN-07 | Dependencias con CVE conocidos (versiones viejas) | `requirements.txt:5-8` | CWE-1104 | A06:2021 – Vulnerable & Outdated Components |

> Nota: son 6 clases distintas de fallo en código + 1 de dependencias (7 en
> total). La guía pide 4–6; se incluyen extras para tener margen tras el triage
> de EX-05.

## Cómo reproducir cada fallo (para las capturas del informe)

- **SQLi (VULN-01):** en `/login`, usuario `admin' -- ` deja pasar sin clave.
- **Command injection (VULN-02):** `GET /ping?host=127.0.0.1;id`
- **Path traversal (VULN-05):** `GET /download?file=../../etc/passwd`
- **Deserialización (VULN-06):** `POST /import` con un YAML `!!python/object/...`
- **Secretos / MD5 / dependencias:** los detecta directamente el escaneo SAST.

## Ejecución local (opcional, solo para demostrar los fallos)

```bash
python -m venv venv
source venv/bin/activate      # en Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py                 # http://127.0.0.1:5000
```

## Flujo de la fase SAST (EX-05)

1. Commit del estado vulnerable → tag `v0-vulnerable` (este estado).
2. Conectar el repo a Snyk o SonarCloud y ejecutar el análisis.
3. Triage de cada hallazgo (verdadero positivo / falso positivo).
4. Corregir los reales y re-escanear (rama de remediación).
5. Documentar el before/after en el informe.
