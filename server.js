import express from "express";
import cors from "cors";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import compression from "compression";
import path from "path";
import QRCode from "qrcode";

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "clave-super-secreta";

app.use(cors());
app.use(express.json());
app.use(compression());

let db;

// ===============================
// 💾 Inicialización de SQLite
// ===============================
const initDB = async () => {
  const dbPath = path.resolve("./asistencia.db");
  db = await open({
    filename: dbPath,
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

  console.log("✅ Base de datos lista");

  // Crear usuarios base
  const admin = await db.get("SELECT * FROM users WHERE username = ?", ["admin"]);
  const scanner = await db.get("SELECT * FROM users WHERE username = ?", ["scanner"]);

  if (!admin) {
    const hash = await bcrypt.hash("admin123", 10);
    await db.run(
      "INSERT INTO users (username, password, role, name) VALUES (?, ?, ?, ?)",
      ["admin", hash, "superadmin", "Administrador Principal"]
    );
    console.log("👑 Usuario admin creado (superadmin)");
  }

  if (!scanner) {
    const hash = await bcrypt.hash("scanner123", 10);
    await db.run(
      "INSERT INTO users (username, password, role, name) VALUES (?, ?, ?, ?)",
      ["scanner", hash, "scanner", "Operador Scanner"]
    );
    console.log("👤 Usuario scanner creado");
  }
};

// ===============================
// 🔐 Middleware JWT
// ===============================
function authenticateToken(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token requerido" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(403).json({ error: "Token inválido o expirado" });
  }
}

// ===============================
// 🔑 Login
// ===============================
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await db.get("SELECT * FROM users WHERE username = ?", [username]);
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "Contraseña incorrecta" });

    const token = jwt.sign(
      { id: user.id, role: user.role, username: user.username },
      JWT_SECRET,
      { expiresIn: "8h" }
    );

    res.json({ token, user });
  } catch (err) {
    console.error("Error login:", err);
    res.status(500).json({ error: "Error en login" });
  }
});

// ===============================
// 👥 CRUD de Usuarios
// ===============================
app.get("/api/users", authenticateToken, async (req, res) => {
  if (req.user.role !== "superadmin")
    return res.status(403).json({ error: "No autorizado" });
  const users = await db.all("SELECT id, username, name, role, created_at FROM users");
  res.json(users);
});

app.post("/api/users", authenticateToken, async (req, res) => {
  if (req.user.role !== "superadmin")
    return res.status(403).json({ error: "No autorizado" });

  const { username, password, name, role } = req.body;
  if (!username || !password || !name)
    return res.status(400).json({ error: "Datos incompletos" });

  try {
    const hash = await bcrypt.hash(password, 10);
    await db.run(
      "INSERT INTO users (username, password, role, name) VALUES (?, ?, ?, ?)",
      [username, hash, role || "scanner", name]
    );
    res.json({ message: "Usuario creado exitosamente" });
  } catch (err) {
    res.status(500).json({ error: "Error al crear usuario" });
  }
});

app.put("/api/users/:id", authenticateToken, async (req, res) => {
  if (req.user.role !== "superadmin")
    return res.status(403).json({ error: "No autorizado" });

  const { id } = req.params;
  const { username, password, role, name } = req.body;
  try {
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      await db.run(
        "UPDATE users SET username=?, password=?, role=?, name=? WHERE id=?",
        [username, hash, role, name, id]
      );
    } else {
      await db.run(
        "UPDATE users SET username=?, role=?, name=? WHERE id=?",
        [username, role, name, id]
      );
    }
    res.json({ message: "Usuario actualizado" });
  } catch {
    res.status(500).json({ error: "Error al actualizar usuario" });
  }
});

app.delete("/api/users/:id", authenticateToken, async (req, res) => {
  if (req.user.role !== "superadmin")
    return res.status(403).json({ error: "No autorizado" });

  try {
    await db.run("DELETE FROM users WHERE id=?", [req.params.id]);
    res.json({ message: "Usuario eliminado" });
  } catch {
    res.status(500).json({ error: "Error al eliminar usuario" });
  }
});

// ===============================
// 👨‍🏭 CRUD de Empleados
// ===============================
app.get("/api/employees", authenticateToken, async (_, res) => {
  const data = await db.all("SELECT * FROM employees ORDER BY id DESC");
  res.json(data);
});

app.get("/api/employees/type/:type", authenticateToken, async (req, res) => {
  const employees = await db.all(
    "SELECT * FROM employees WHERE employee_type=?",
    [req.params.type]
  );
  res.json(employees);
});

app.get("/api/employees/:id/qr", authenticateToken, async (req, res) => {
  try {
    const employee = await db.get("SELECT * FROM employees WHERE id=?", [req.params.id]);
    if (!employee) return res.status(404).json({ error: "Empleado no encontrado" });

    const qrImage = await QRCode.toDataURL(employee.qr_code);
    res.json({ qr: qrImage });
  } catch {
    res.status(500).json({ error: "Error generando QR" });
  }
});

app.post("/api/employees", authenticateToken, async (req, res) => {
  const { dni, first_name, last_name, employee_type, qr_code, salario_mensual } = req.body;
  try {
    await db.run(
      "INSERT INTO employees (dni, first_name, last_name, employee_type, qr_code, salario_mensual) VALUES (?, ?, ?, ?, ?, ?)",
      [dni, first_name, last_name, employee_type, qr_code, salario_mensual]
    );
    res.json({ message: "Empleado agregado correctamente" });
  } catch {
    res.status(500).json({ error: "Error al agregar empleado" });
  }
});

app.put("/api/employees/:id", authenticateToken, async (req, res) => {
  const { dni, first_name, last_name, employee_type, salario_mensual } = req.body;
  try {
    await db.run(
      "UPDATE employees SET dni=?, first_name=?, last_name=?, employee_type=?, salario_mensual=? WHERE id=?",
      [dni, first_name, last_name, employee_type, salario_mensual, req.params.id]
    );
    res.json({ message: "Empleado actualizado correctamente" });
  } catch {
    res.status(500).json({ error: "Error al actualizar empleado" });
  }
});

app.delete("/api/employees/:id", authenticateToken, async (req, res) => {
  try {
    await db.run("DELETE FROM employees WHERE id=?", [req.params.id]);
    res.json({ message: "Empleado eliminado" });
  } catch {
    res.status(500).json({ error: "Error al eliminar empleado" });
  }
});

// ===============================
// ⏱️ Asistencia
// ===============================
app.post("/api/attendance", authenticateToken, async (req, res) => {
  const { employee_id, record_type, record_date, record_time } = req.body;
  try {
    await db.run(
      "INSERT INTO attendance (employee_id, record_type, record_date, record_time) VALUES (?, ?, ?, ?)",
      [employee_id, record_type, record_date, record_time]
    );
    res.json({ message: "Registro guardado correctamente" });
  } catch {
    res.status(500).json({ error: "Error al guardar asistencia" });
  }
});

// ===============================
// 📊 Dashboard
// ===============================
app.get("/api/dashboard/stats", authenticateToken, async (_, res) => {
  const totalEmployees = await db.get("SELECT COUNT(*) AS count FROM employees");
  const totalRecords = await db.get("SELECT COUNT(*) AS count FROM attendance");
  res.json({
    totalEmployees: totalEmployees.count,
    totalRecords: totalRecords.count,
  });
});

// ===============================
// 🚀 Servidor
// ===============================
app.get("/", (_, res) =>
  res.send("✅ Backend conectado a SQLite con CRUD completo y roles activos 🚀")
);

app.listen(PORT, async () => {
  await initDB();
  console.log(`🔥 Servidor corriendo en puerto ${PORT}`);
});
