# EX-05 — SAST: triage y remediación

Estado "after". Cada corrección (`# FIX-0x`) se corresponde con el fallo
`# VULN-0x` del baseline `v0-vulnerable`.

## Tabla de triage (verdadero positivo / falso positivo)

Todos los fallos plantados son **verdaderos positivos** (por diseño). Se incluye
también un ejemplo de cómo justificar un falso positivo, porque la guía pide que
el triage muestre ese criterio.

| ID | Regla / CWE | ¿Verdadero positivo? | Justificación |
|----|-------------|----------------------|---------------|
| S-01 | SQLi · CWE-89 | Sí | `username` del formulario llega sin sanear a una consulta construida por concatenación (`app.py:62`). |
| S-02 | Command injection · CWE-78 | Sí | `host` de la query se pasa a `os.popen` con la shell (`app.py:86`); `;id` se ejecuta. |
| S-03 | Hardcoded secret · CWE-798 | Sí | `secret_key` y API key literales versionadas en git (`app.py:19-20`). |
| S-04 | Weak hash · CWE-327 | Sí | Contraseñas con MD5 sin sal (`app.py:38,58`); roto y sin coste. |
| S-05 | Path traversal · CWE-22 | Sí | `file` concatenado a la ruta sin validar (`app.py:95`); `../../etc/passwd` sale del directorio. |
| S-06 | Insecure deserialization · CWE-502 | Sí | `yaml.load` sin `SafeLoader` instancia objetos arbitrarios (`app.py:105`). |
| S-07 | Vulnerable dependencies · CWE-1104 | Sí | Flask/PyYAML/requests/Werkzeug con CVE conocidos (`requirements.txt`). |
| S-08 | *(ejemplo de falso positivo)* | **Falso positivo** | *Ej.: la herramienta marca `debug=True` en un archivo de test que nunca se despliega → se documenta y no se corrige.* |

## Tabla de remediación (before → after)

| ID | CWE | Archivo:línea | Severidad | Fix aplicado |
|----|-----|---------------|-----------|--------------|
| S-01 | CWE-89 | `app.py:74` | ALTA | Consulta parametrizada con `?` y verificación del hash aparte. |
| S-02 | CWE-78 | `app.py:93-99` | ALTA | Lista blanca de caracteres (`HOSTNAME_RE`) + `subprocess.run` con lista de argumentos, sin shell. |
| S-03 | CWE-798 | `app.py:24-25` | ALTA | Secretos leídos de variables de entorno (`os.environ`); `.env.example` documenta las claves. |
| S-04 | CWE-327 | `app.py:50,79` | ALTA | `bcrypt.hashpw` / `bcrypt.checkpw` (sal automática, coste configurable). |
| S-05 | CWE-22 | `app.py:110` | MEDIA | Ruta normalizada con `abspath` y verificación de que siga dentro de `FILES_DIR`. |
| S-06 | CWE-502 | `app.py:124` | ALTA | `yaml.safe_load` en lugar de `yaml.load`. |
| S-07 | CWE-1104 | `requirements.txt` | ALTA | Versiones actualizadas: Flask 3.0.3, PyYAML 6.0.2, requests 2.32.3, Werkzeug 3.0.4. |

> Los números de línea de la columna "after" son los del archivo corregido
> (`vuln-portal-fixed/app.py`). Verifícalos con `grep -n "FIX-" app.py` por si
> editan el archivo.

## Estado final esperado tras re-escanear

- Cero hallazgos verdaderos-positivos **High/Critical** abiertos.
- Lo que quede debe ser un fallo corregido (con enlace al commit) o un falso
  positivo justificado — nada suprimido en silencio.
- Adjuntar captura del escaneo final + enlace a la rama de remediación.

## Cómo aplicar la remediación en git (después de taggear `v0-vulnerable`)

```bash
# Ya en el repo, con v0-vulnerable commiteado y taggeado:
git checkout -b fix/sast-remediation

# Copiar los archivos corregidos sobre los originales:
#   app.py, requirements.txt, .env.example
# (desde vuln-portal-fixed/)

git add -A
git commit -m "fix: remediar hallazgos SAST (SQLi, cmd injection, secretos, MD5, path traversal, yaml, deps)"
git push -u origin fix/sast-remediation
```

Re-escanear esta rama con Snyk/SonarCloud y capturar el resultado final.
