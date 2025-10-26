# Usa una imagen limpia de Node.js
FROM node:22

WORKDIR /app

# Copia los archivos de dependencias
COPY package*.json ./

# Configura un registro alternativo y desactiva la verificación de integridad
RUN npm config set registry https://registry.npmmirror.com \
    && npm config set strict-ssl false \
    && npm config set legacy-peer-deps true \
    && npm config set fetch-retries 5 \
    && npm config set fetch-retry-factor 3 \
    && npm config set fetch-timeout 30000 \
    && npm config set cache /tmp/npm-cache --global \
    && npm cache clean --force \
    && npm install --omit=dev --no-audit --no-fund

# Copia el resto del proyecto
COPY . .

EXPOSE 8080

CMD ["npm", "start"]
