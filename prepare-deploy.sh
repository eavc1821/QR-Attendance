#!/bin/bash

echo "🚀 Preparando proyecto para deploy en Render..."

# 1️⃣ Elimina node_modules y package-lock.json
echo "🧹 Limpiando dependencias locales..."
rm -rf node_modules package-lock.json

# 2️⃣ Instala dependencias desde cero
echo "📦 Instalando dependencias..."
npm install

# 3️⃣ Fuerza la recompilación de sqlite3 desde el código fuente
echo "🔧 Recompilando sqlite3 para Linux..."
npm rebuild sqlite3 --build-from-source

echo "✅ Proyecto listo para deploy en Render."
