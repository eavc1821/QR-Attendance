# Usa la imagen oficial de Node
FROM node:22

# Establece el directorio de trabajo
WORKDIR /app

# Copia los archivos necesarios
COPY package*.json ./

# Instala dependencias con npm install (evita npm ci)
RUN npm install --omit=dev --legacy-peer-deps --no-audit --no-fund

# Copia el resto del proyecto
COPY . .

# Expone el puerto que usa Railway
EXPOSE 8080

# Arranca el servidor
CMD ["npm", "start"]
