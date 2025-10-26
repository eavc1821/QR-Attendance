# ---------- Etapa base ----------
FROM node:22-alpine AS base

WORKDIR /app
COPY package*.json ./

# Configuración del cache de npm (para evitar corrupción de paquetes)
RUN npm config set registry https://registry.npmjs.org/ \
    && npm config set fetch-retries 5 \
    && npm config set fetch-retry-factor 3 \
    && npm config set fetch-timeout 30000 \
    && npm install --omit=dev --no-audit --no-fund

COPY . .

# Puerto (Railway usa 8080 por defecto)
ENV PORT=8080
EXPOSE 8080

CMD ["node", "server.js"]
