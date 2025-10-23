import express from "express";
import cors from "cors";
import sqlite3 from "sqlite3";
import { open } from "sqlite";

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Conexión con SQLite
let db;
(async () => {
  db = await open({
    filename: process.env.DB_PATH || "./database.sqlite",
    driver: sqlite3.Database
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nombre TEXT,
      email TEXT,
      fecha_registro TEXT
    )
  `);
})();

// Rutas
app.get("/", (req, res) => {
  res.send("Servidor Express funcionando en Railway ✅");
});

app.get("/api/usuarios", async (req, res) => {
  try {
    const usuarios = await db.all("SELECT * FROM usuarios");
    res.json(usuarios);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor en puerto ${PORT}`);
});
