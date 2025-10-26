import express from "express";
import cors from "cors";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import compression from "compression";

// ===============================
// 🔧 Configuración general
// ===============================
const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "clave-super-secreta";

app.use(cors());
app.use(express.json());
app.use(compression());

// ===============================
// 💾 Inicializar base de datos SQLite
// ===============================
let db;

const initDB = async () => {
  db = await open({
    filename: "./database.db",
    driver: sqlite3.Database,
  });

  // Crear tablas si no existen
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS employees (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      position TEXT,
      department TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS attendance (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      employee_id INTEGER NOT NULL,
      record_type TEXT NOT NULL,
      record_date DATE NOT NULL,
      record_time TIME NOT NULL,
      bags_elaborated INTEGER DEFAULT NULL,
      despalillo INTEGER DEFAULT NULL,
      escogida INTEGER DEFAULT NULL,
      moniado INTEGER DEFAULT NULL,
      horas_extras INTEGER DEFAULT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (employee_id) REFERENCES employees (id)
    );
  `);

  console.log("✅ Tablas creadas o existentes");

  // Crear usuario admin si no existe
  const admin = await db.get("SELECT * FROM users WHERE username = ?", ["admin"]);
  if (!admin) {
    const hash = await bcrypt.hash("admin123", 10);
    await db.run(
      "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
      ["admin", hash, "admin"]
    );
    console.log("👑 Usuario admin creado: admin / admin123");
  } else {
    console.log("🔹 Usuario admin ya existe");
  }

  return db;
};

// ===============================
// 🔐 Login (Autenticación)
// ===============================
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await db.get("SELECT * FROM users WHERE username = ?", [username]);
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "Contraseña incorrecta" });

    const token = jwt.sign(
      { id: user.id, role: user.role },
      JWT_SECRET,
      { expiresIn: "8h" }
    );

    res.json({ token, user });
  } catch (err) {
    console.error("❌ Error en login:", err);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// ===============================
// 👥 Empleados
// ===============================
app.get("/api/employees", async (req, res) => {
  try {
    const rows = await db.all("SELECT * FROM employees ORDER BY id DESC");
    res.json(rows);
  } catch (err) {
    console.error("❌ Error al obtener empleados:", err);
    res.status(500).json({ error: "Error al obtener empleados" });
  }
});

app.post("/api/employees", async (req, res) => {
  const { name, position, department } = req.body;
  try {
    await db.run(
      "INSERT INTO employees (name, position, department) VALUES (?, ?, ?)",
      [name, position, department]
    );
    res.json({ message: "Empleado registrado correctamente" });
  } catch (err) {
    console.error("❌ Error al registrar empleado:", err);
    res.status(500).json({ error: "Error al registrar empleado" });
  }
});

// ===============================
// ⏱️ Asistencias
// ===============================
app.post("/api/attendance", async (req, res) => {
  const {
    employee_id,
    record_type,
    record_date,
    record_time,
    bags_elaborated,
    despalillo,
    escogida,
    moniado,
    horas_extras,
  } = req.body;

  try {
    await db.run(
      `INSERT INTO attendance 
      (employee_id, record_type, record_date, record_time, bags_elaborated, despalillo, escogida, moniado, horas_extras)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        employee_id,
        record_type,
        record_date,
        record_time,
        bags_elaborated,
        despalillo,
        escogida,
        moniado,
        horas_extras,
      ]
    );
    res.json({ message: "Registro de asistencia exitoso" });
  } catch (err) {
    console.error("❌ Error al registrar asistencia:", err);
    res.status(500).json({ error: "Error al registrar asistencia" });
  }
});

// ===============================
// 📊 Dashboard / estadísticas
// ===============================
app.get("/api/dashboard/stats", async (req, res) => {
  try {
    const totalEmployees = await db.get("SELECT COUNT(*) as count FROM employees");
    const totalRecords = await db.get("SELECT COUNT(*) as count FROM attendance");

    res.json({
      totalEmployees: totalEmployees.count,
      totalRecords: totalRecords.count,
    });
  } catch (err) {
    console.error("❌ Error al obtener estadísticas:", err);
    res.status(500).json({ error: "Error al obtener estadísticas" });
  }
});

// ===============================
// 🧠 Verificación básica
// ===============================
app.get("/", (req, res) => {
  res.send("✅ Backend con SQLite operativo 🚀");
});

// ===============================
// 🚀 Iniciar servidor
// ===============================
app.listen(PORT, async () => {
  await initDB();
  console.log(`🔥 Servidor corriendo en puerto ${PORT}`);
});
