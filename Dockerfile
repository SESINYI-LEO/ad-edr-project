FROM node:20-slim AS ui
WORKDIR /ui
COPY frontend/package*.json ./
RUN npm ci || npm install
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server ./server
COPY lab ./lab
COPY run_server.py .
COPY --from=ui /ui/dist ./frontend/dist
ENV HOST=0.0.0.0 PORT=8000 BACKUP_DIR=/data/backups
EXPOSE 8000
CMD ["python", "run_server.py"]
