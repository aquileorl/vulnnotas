# VulnNotas — aplicación web deliberadamente vulnerable (TFG Bloque II)

**Alumno:** Emilio José Ruiz Linares · thePower Business School (2025-2026)
**Bloque II — Desarrollo Seguro.** App propia (Flask + SQLite) con vulnerabilidades
OWASP Top 10 **intencionadas** para practicar SAST, DAST, CVSS, modelado de amenazas,
pipeline DevSecOps y corrección de vulnerabilidades.

> ⚠️ **Uso exclusivo en laboratorio aislado.** Contiene fallos de seguridad a propósito.
> No desplegar en producción ni en redes accesibles desde Internet.

## Descripción funcional
Intranet mínima de notas de empleados: login, listado/creación/búsqueda de notas,
vista de nota, panel de administración y un par de utilidades (ping, importar YAML).

## Mapa de vulnerabilidades intencionadas (OWASP Top 10:2021)

| ID | Vulnerabilidad | OWASP | Dónde (código) | Detectada por |
|----|----------------|-------|----------------|---------------|
| V1 | **SQL Injection** (login) | A03 | `login()` — query por concatenación | SAST (Semgrep/Bandit B608) + DAST |
| V2 | **SQL Injection** (búsqueda / insert / id) | A03 | `notes()`, `new_note()`, `note()` | SAST + DAST |
| V3 | **XSS reflejado** | A03 | `notes.html` (`{{ q|safe }}`) | DAST (ZAP) |
| V4 | **XSS almacenado** | A03 | `note.html` (`{{ note.body|safe }}`) | DAST (ZAP) |
| V5 | **IDOR / Broken Access Control** | A01 | `note()` sin comprobar propietario | Manual / revisión |
| V6 | **Falta de control de rol** | A01 | `admin()` sin verificar `role` | Manual / revisión |
| V7 | **Secretos hardcodeados** | A02 | `SECRET_KEY`, claves AWS, password | Gitleaks + SAST |
| V8 | **Contraseñas en texto plano** | A02 | `init_db()` / tabla `users` | SAST / revisión |
| V9 | **Command Injection** | A03 | `ping()` `subprocess(..., shell=True)` | SAST (Bandit B602/B605) |
| V10 | **Deserialización insegura** | A08 | `import_yaml()` `yaml.load` | SAST (Bandit B506) |
| V11 | **Componentes vulnerables** | A06 | `requirements.txt` (PyYAML 5.3.1, requests 2.20…) | SCA (pip-audit/Dependency-Check) |
| V12 | **Security Misconfiguration** | A05 | `debug=True`, sin cabeceras, imagen base antigua | DAST + Trivy |

## Ejecución local
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python app.py                 # http://127.0.0.1:5000  (usuarios: emilio/flask2026, guest/guest)
```
Con Docker:
```bash
docker build -t vulnnotas .
docker run --rm -p 5000:5000 vulnnotas
```

## Pipeline DevSecOps (GitHub Actions)
`.github/workflows/devsecops.yml` ejecuta **5 etapas de seguridad**:
1. **SAST** — Semgrep (`p/owasp-top-ten`, `p/python`) + Bandit.
2. **SCA** — pip-audit sobre `requirements.txt`.
3. **Secretos** — Gitleaks.
4. **Imagen Docker** — Trivy (CVEs de SO y librerías).
5. **DAST** — OWASP ZAP baseline contra la app en ejecución.

## Correcciones (Bloque II, §5.5)
Las correcciones (≥3) se documentan con *diff* antes/después en el informe del bloque
(rama/commit de fix): consultas parametrizadas, escapado de salida, control de acceso,
`yaml.safe_load`, gestión de secretos por variables de entorno y `debug=False`.
