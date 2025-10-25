// ============================================
// 🚀 Backend Express + PostgreSQL (Railway)
// ============================================

import express from "express";
import cors from "cors";
import pkg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const { Pool } = pkg;

// ==========================
// 🔌 CONEXIÓN A POSTGRESQL
// ==========================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Wrappers de compatibilidad (para mantener el mismo formato que SQLite)
const db = {
  get: async (query, params = []) => {
    const { rows } = await pool.query(query, params);
    return rows[0];
  },
  all: async (query, params = []) => {
    const { rows } = await pool.query(query, params);
    return rows;
  },
  run: async (query, params = []) => {
    await pool.query(query, params);
  },
};

// ==========================
// ⚙️ CONFIGURACIÓN EXPRESS
// ==========================
const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "clave_super_segura";

app.use(cors());
app.use(express.json());

// ==========================
// 🧱 CREACIÓN DE TABLAS
// ==========================
(async () => {
  try {
    await db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'user',
        name VARCHAR(100)
      );
    `);

    await db.run(`
      CREATE TABLE IF NOT EXISTS employees (
        id SERIAL PRIMARY KEY,
        first_name VARCHAR(100) NOT NULL,
        last_name VARCHAR(100) NOT NULL,
        employee_type VARCHAR(50),
        qr_code TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await db.run(`
      CREATE TABLE IF NOT EXISTS attendance (
        id SERIAL PRIMARY KEY,
        employee_id INTEGER REFERENCES employees(id),
        record_type VARCHAR(50) NOT NULL,
        record_date DATE NOT NULL,
        record_time TIME NOT NULL,
        bags_elaborated INTEGER DEFAULT NULL,
        despalillo INTEGER DEFAULT NULL,
        escogida INTEGER DEFAULT NULL,
        moniado INTEGER DEFAULT NULL,
        horas_extras INTEGER DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // ==========================
    // 👑 CREAR SUPERADMIN POR DEFECTO
    // ==========================
    const adminExists = await db.get(
      "SELECT * FROM users WHERE username = 'admin'"
    );
    if (!adminExists) {
      const hashed = bcrypt.hashSync("admin123", 10);
      await db.run(
        "INSERT INTO users (username, password, role, name) VALUES ($1, $2, $3, $4)",
        ["admin", hashed, "superadmin", "Administrador General"]
      );
      console.log("👑 Usuario superadmin creado (admin / admin123)");
    } else {
      console.log("✅ Usuario admin ya existe, no se crea duplicado.");
    }

    console.log("✅ Tablas listas en PostgreSQL");
  } catch (err) {
    console.error("❌ Error al crear tablas:", err);
  }
})();

// ==========================
// 🔐 MIDDLEWARE AUTENTICACIÓN JWT
// ==========================
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token requerido" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Token inválido" });
    req.user = user;
    next();
  });
}

// ==========================
// 🔑 LOGIN
// ==========================
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await db.get("SELECT * FROM users WHERE username = $1", [
      username,
    ]);

    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    const validPassword = bcrypt.compareSync(password, user.password);
    if (!validPassword)
      return res.status(401).json({ error: "Contraseña incorrecta" });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: "8h" }
    );

    res.json({
      message: "Login exitoso",
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        name: user.name,
      },
    });
  } catch (err) {
    res.status(500).json({ error: "Error interno en login" });
  }
});

// ==========================
// 👥 GESTIÓN DE EMPLEADOS
// ==========================
app.get("/api/employees", authenticateToken, async (req, res) => {
  try {
    const employees = await db.all("SELECT * FROM employees ORDER BY id DESC");
    res.json(employees);
  } catch (err) {
    res.status(500).json({ error: "Error al obtener empleados" });
  }
});

app.post("/api/employees", authenticateToken, async (req, res) => {
  const { first_name, last_name, employee_type } = req.body;
  try {
    await db.run(
      "INSERT INTO employees (first_name, last_name, employee_type) VALUES ($1, $2, $3)",
      [first_name, last_name, employee_type]
    );
    res.json({ message: "Empleado agregado" });
  } catch (err) {
    res.status(500).json({ error: "Error al agregar empleado" });
  }
});

// ==========================
// 🕒 REGISTROS DE ASISTENCIA
// ==========================
app.get("/api/attendance", authenticateToken, async (req, res) => {
  try {
    const records = await db.all(`
      SELECT a.*, e.first_name, e.last_name
      FROM attendance a
      JOIN employees e ON a.employee_id = e.id
      ORDER BY a.record_date DESC, a.record_time DESC
      LIMIT 100;
    `);
    res.json(records);
  } catch (err) {
    res.status(500).json({ error: "Error al obtener registros" });
  }
});

// ==========================
// 📊 DASHBOARD / ESTADÍSTICAS
// ==========================
app.get("/api/dashboard/stats", authenticateToken, async (req, res) => {
  try {
    const totalEmployees = await db.get(
      "SELECT COUNT(*) AS total FROM employees"
    );
    const today = new Date().toISOString().split("T")[0];
    const totalRecords = await db.get(
      "SELECT COUNT(*) AS total FROM attendance WHERE record_date = $1",
      [today]
    );
    res.json({
      total_employees: totalEmployees.total || 0,
      today_records: totalRecords.total || 0,
    });
  } catch (err) {
    res.status(500).json({ error: "Error obteniendo estadísticas" });
  }
});

// ==========================
// 🧩 SALUD DEL SERVIDOR
// ==========================
app.get("/api/health", (req, res) => {
  res.json({ status: "Servidor activo 🚀" });
});

// ==========================
// 🚀 INICIAR SERVIDOR
// ==========================
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
});
