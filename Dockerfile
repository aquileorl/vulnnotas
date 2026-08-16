# Imagen base antigua a proposito (A06) para que Trivy reporte CVEs de SO y librerias.
FROM python:3.8-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

EXPOSE 5000
# Nota: se ejecuta como root y con debug=True (malas practicas INTENCIONADAS).
CMD ["python", "app.py"]
