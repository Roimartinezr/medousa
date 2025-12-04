# Imagen base ligera con Python
FROM python:3.11-slim

# Directorio de trabajo
WORKDIR /app

# Instala dependencias
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
RUN playwright install chromium
RUN playwright install-deps chromium

# Copia el código fuente
COPY . .

# Expone el puerto interno
EXPOSE 8000

# Lanza el servidor con waitress
CMD ["waitress-serve", "--port=8000", "--host=0.0.0.0", "app:app"]