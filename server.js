import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { open } from "sqlite";
import sqlite3 from "sqlite3";
import compression from "compression";
import QRCode from "qrcode";

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

app.use(cors());
app.use(express.json());
app.use(compression());

let db;

// 🧱 Inicializar base de datos SQLite
const initDB = async () => {
  db = await open({
    filename: "./database.sqlite",
    driver: sqlite3.Database,
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'scanner',
      name TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await db.exec(`
    CREATE TABLE IF NOT EXISTS employees (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      dni TEXT UNIQUE NOT NULL,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      employee_type TEXT NOT NULL,
      photo TEXT,
      qr_code TEXT UNIQUE NOT NULL,
      salario_mensual DECIMAL(10,2) DEFAULT NULL,
      qr_image TEXT DEFAULT NULL,
      is_active BOOLEAN DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await db.exec(`
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

  // 👑 Crear superadmin si no existe
  const admin = await db.get("SELECT * FROM users WHERE username = 'admin'");
  if (!admin) {
    const hashedPassword = await bcrypt.hash("admin123", 10);
    await db.run(
      "INSERT INTO users (username, password, role, name) VALUES (?, ?, ?, ?)",
      ["admin", hashedPassword, "superadmin", "Administrador General"]
    );
    console.log("✅ Usuario superadmin creado: admin / admin123");
  }
};

// 🛡️ Middleware de autenticación JWT
const authenticate = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token no proporcionado" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Token inválido" });
    req.user = user;
    next();
  });
};

// 👤 LOGIN
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await db.get("SELECT * FROM users WHERE username = ?", [username]);
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "Contraseña incorrecta" });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: "8h" }
    );

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        name: user.name,
        role: user.role,
      },
    });
  } catch (err) {
    console.error("❌ Error en login:", err);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

// 👥 CRUD de usuarios (solo superadmin)
app.get("/api/users", authenticate, async (req, res) => {
  if (req.user.role !== "superadmin") return res.status(403).json({ error: "Acceso denegado" });
  const users = await db.all("SELECT id, username, role, name, created_at FROM users");
  res.json(users);
});

app.post("/api/users", authenticate, async (req, res) => {
  if (req.user.role !== "superadmin") return res.status(403).json({ error: "Acceso denegado" });
  const { username, password, role, name } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  await db.run(
    "INSERT INTO users (username, password, role, name) VALUES (?, ?, ?, ?)",
    [username, hashed, role, name]
  );
  res.json({ message: "Usuario creado correctamente" });
});

app.put("/api/users/:id", authenticate, async (req, res) => {
  if (req.user.role !== "superadmin") return res.status(403).json({ error: "Acceso denegado" });
  const { username, password, role, name } = req.body;
  const { id } = req.params;

  if (password) {
    const hashed = await bcrypt.hash(password, 10);
    await db.run(
      "UPDATE users SET username = ?, password = ?, role = ?, name = ? WHERE id = ?",
      [username, hashed, role, name, id]
    );
  } else {
    await db.run(
      "UPDATE users SET username = ?, role = ?, name = ? WHERE id = ?",
      [username, role, name, id]
    );
  }
  res.json({ message: "Usuario actualizado correctamente" });
});

app.delete("/api/users/:id", authenticate, async (req, res) => {
  if (req.user.role !== "superadmin") return res.status(403).json({ error: "Acceso denegado" });
  const { id } = req.params;
  await db.run("DELETE FROM users WHERE id = ?", [id]);
  res.json({ message: "Usuario eliminado correctamente" });
});


// 👥 CRUD de empleados
app.get("/api/employees", authenticate, async (req, res) => {
  try {
    const employees = await db.all("SELECT * FROM employees WHERE is_active = 1");
    res.json(employees);
  } catch (err) {
    res.status(500).json({ error: "Error obteniendo empleados" });
  }
});

app.post("/api/employees", authenticate, async (req, res) => {
  try {
    const { dni, first_name, last_name, employee_type, salario_mensual } = req.body;
    const qr_code = `${dni}-${Date.now()}`;
    const qr_image = await QRCode.toDataURL(qr_code);

    await db.run(
      `INSERT INTO employees (dni, first_name, last_name, employee_type, salario_mensual, qr_code, qr_image)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [dni, first_name, last_name, employee_type, salario_mensual, qr_code, qr_image]
    );

    res.json({ message: "Empleado registrado correctamente" });
  } catch (err) {
    console.error("❌ Error al registrar empleado:", err);
    res.status(500).json({ error: "Error registrando empleado" });
  }
});

// 📅 Registros de asistencia
app.get("/api/attendance", authenticate, async (req, res) => {
  try {
    const records = await db.all(`
      SELECT a.*, e.first_name, e.last_name
      FROM attendance a
      JOIN employees e ON a.employee_id = e.id
      ORDER BY a.created_at DESC
    `);
    res.json(records);
  } catch (err) {
    console.error("❌ Error obteniendo registros:", err);
    res.status(500).json({ error: "Error obteniendo registros" });
  }
});

// 📊 Estadísticas para el dashboard
app.get("/api/dashboard/stats", authenticate, async (req, res) => {
  try {
    const totalEmployees = await db.get("SELECT COUNT(*) as count FROM employees WHERE is_active = 1");
    const totalRecords = await db.get("SELECT COUNT(*) as count FROM attendance");
    const todayRecords = await db.get(
      "SELECT COUNT(*) as count FROM attendance WHERE record_date = date('now')"
    );

    res.json({
      totalEmployees: totalEmployees.count,
      totalRecords: totalRecords.count,
      todayRecords: todayRecords.count,
    });
  } catch (err) {
    console.error("❌ Error en estadísticas:", err);
    res.status(500).json({ error: "Error obteniendo estadísticas" });
  }
});

// 🚀 Iniciar servidor
initDB()
  .then(() => {
    app.listen(PORT, () => console.log(`✅ Servidor en puerto ${PORT}`));
  })
  .catch((err) => console.error("❌ Error al iniciar la base de datos:", err));
