import express from "express";
import cors from "cors";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "clave_super_segura";

app.use(cors({ origin: "*", credentials: true }));
app.use(express.json());

// ==========================
// 🗄️ BASE DE DATOS
// ==========================
let db;
(async () => {
  db = await open({
    filename: "./database.sqlite",
    driver: sqlite3.Database,
  });

  // Crear tablas si no existen
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL,
      name TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await db.exec(`
    CREATE TABLE IF NOT EXISTS employees (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      dni TEXT UNIQUE,
      employee_type TEXT,
      qr_code TEXT UNIQUE,
      salario_mensual REAL DEFAULT 0
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

  
  // ==========================
  // 👤 CREAR USUARIO ADMIN POR DEFECTO
  // ==========================
  // 👑 CREAR USUARIO SUPERADMIN POR DEFECTO
try {
  const adminExists = await db.get("SELECT * FROM users WHERE username = 'admin'");
  if (!adminExists) {
    const hashedPassword = bcrypt.hashSync("admin123", 10);
    await db.run(
      "INSERT INTO users (username, password, role, name) VALUES (?, ?, ?, ?)",
      ["admin", hashedPassword, "superadmin", "Administrador General"]
    );
    console.log("👑 Usuario superadmin creado por defecto (admin / admin123)");
  } else {
    console.log("✅ Usuario admin ya existe, no se crea duplicado.");
  }
} catch (err) {
  console.error("❌ Error al verificar o crear usuario admin:", err);
}


  console.log("✅ Base de datos inicializada");
})();




// ==========================
// 🔐 AUTENTICACIÓN
// ==========================
function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: "12h" }
  );
}

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
// 🔑 LOGIN Y TOKEN
// ==========================
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await db.get("SELECT * FROM users WHERE username = ?", [username]);
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "Contraseña incorrecta" });

    const token = generateToken(user);
    res.json({
      message: "Login exitoso",
      token,
      user: { id: user.id, username: user.username, role: user.role, name: user.name },
    });
  } catch (err) {
    console.error("Error en login:", err);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

app.get("/api/verify-token", authenticateToken, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// ==========================
// 👥 USUARIOS
// ==========================
app.get("/api/users", authenticateToken, async (req, res) => {
  try {
    const users = await db.all("SELECT id, username, role, name, created_at FROM users");
    res.json(users);
  } catch {
    res.status(500).json({ error: "Error al obtener usuarios" });
  }
});

app.post("/api/users", authenticateToken, async (req, res) => {
  const { username, password, role, name } = req.body;
  if (!username || !password || !role)
    return res.status(400).json({ error: "Todos los campos son requeridos" });

  const hashed = bcrypt.hashSync(password, 10);
  try {
    const result = await db.run(
      "INSERT INTO users (username, password, role, name) VALUES (?, ?, ?, ?)",
      [username, hashed, role, name]
    );
    res.status(201).json({ id: result.lastID, username, role, name });
  } catch {
    res.status(500).json({ error: "Error al crear usuario" });
  }
});

app.put("/api/users/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { username, password, role, name } = req.body;
  try {
    const user = await db.get("SELECT * FROM users WHERE id = ?", [id]);
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });
    const hashed = password ? bcrypt.hashSync(password, 10) : user.password;
    await db.run(
      "UPDATE users SET username = ?, password = ?, role = ?, name = ? WHERE id = ?",
      [username, hashed, role, name, id]
    );
    res.json({ message: "Usuario actualizado" });
  } catch {
    res.status(500).json({ error: "Error al actualizar usuario" });
  }
});

app.delete("/api/users/:id", authenticateToken, async (req, res) => {
  try {
    await db.run("DELETE FROM users WHERE id = ?", [req.params.id]);
    res.json({ message: "Usuario eliminado" });
  } catch {
    res.status(500).json({ error: "Error al eliminar usuario" });
  }
});

// ==========================
// 🕒 ASISTENCIA
// ==========================
app.get("/api/attendance", authenticateToken, (req, res) => {
  const { date, limit } = req.query;
  let query = `
    SELECT a.*, e.first_name, e.last_name, e.employee_type
    FROM attendance a
    JOIN employees e ON a.employee_id = e.id
  `;
  const params = [];
  if (date) {
    query += " WHERE a.record_date = ?";
    params.push(date);
  }
  query += " ORDER BY a.record_date DESC, a.record_time DESC";
  if (limit) {
    query += " LIMIT ?";
    params.push(parseInt(limit));
  }

  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: "Error al obtener registros" });
    res.json(rows);
  });
});

app.post("/api/attendance", (req, res) => {
  const { qr_code, employee_id, record_type, bags_elaborated, despalillo, escogida, moniado, horas_extras } = req.body;
  if (!qr_code && !employee_id)
    return res.status(400).json({ error: "Se requiere qr_code o employee_id" });
  if (!record_type)
    return res.status(400).json({ error: "El tipo de registro es requerido" });

  const queryEmp = qr_code
    ? "SELECT id, first_name, last_name FROM employees WHERE qr_code = ?"
    : "SELECT id, first_name, last_name FROM employees WHERE id = ?";
  const param = qr_code ? qr_code : employee_id;

  db.get(queryEmp, [param], (err, employee) => {
    if (err || !employee) return res.status(404).json({ error: "Empleado no encontrado" });

    const now = new Date();
    const record_date = now.toISOString().split("T")[0];
    const record_time = now.toTimeString().split(" ")[0];

    db.run(
      `INSERT INTO attendance (employee_id, record_type, record_date, record_time, bags_elaborated, despalillo, escogida, moniado, horas_extras)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [employee.id, record_type, record_date, record_time, bags_elaborated, despalillo, escogida, moniado, horas_extras],
      function (err2) {
        if (err2) return res.status(500).json({ error: "Error al registrar asistencia" });
        res.status(201).json({
          message: "Registro de asistencia creado correctamente",
          id: this.lastID,
          employee,
          record_type,
          record_date,
          record_time,
        });
      }
    );
  });
});

// 📊 Estadísticas de asistencia
app.get("/api/attendance/stats", authenticateToken, (req, res) => {
  const { start_date, end_date } = req.query;
  let whereClause = "";
  const params = [];
  if (start_date && end_date) {
    whereClause = "WHERE record_date BETWEEN ? AND ?";
    params.push(start_date, end_date);
  }

  const stats = {};
  db.get(`SELECT COUNT(*) as total FROM attendance ${whereClause}`, params, (err, row) => {
    stats.totalRecords = row?.total || 0;
    db.get(
      `SELECT SUM(CASE WHEN record_type='entrada' THEN 1 ELSE 0 END) as entradas,
              SUM(CASE WHEN record_type='salida' THEN 1 ELSE 0 END) as salidas
       FROM attendance ${whereClause}`,
      params,
      (err2, r2) => {
        stats.recordsByType = r2;
        res.json(stats);
      }
    );
  });
});

// 🧹 Limpieza
app.delete("/api/attendance/cleanup", authenticateToken, (req, res) => {
  const { start_date, end_date, confirmation } = req.body;
  if (confirmation !== "ELIMINAR_REGISTROS")
    return res.status(400).json({ error: "Confirmación inválida" });

  let where = "";
  const params = [];
  if (start_date && end_date) {
    where = "WHERE record_date BETWEEN ? AND ?";
    params.push(start_date, end_date);
  }

  db.run(`DELETE FROM attendance ${where}`, params, function (err) {
    if (err) return res.status(500).json({ error: "Error al eliminar registros" });
    res.json({ message: "Registros eliminados", deleted: this.changes });
  });
});

// ==========================
// 📈 REPORTES
// ==========================
app.get("/api/reports/quick-stats", authenticateToken, (req, res) => {
  const today = new Date().toISOString().split("T")[0];
  const result = {};
  db.get("SELECT COUNT(*) as total FROM employees", [], (err, e) => {
    result.totalEmployees = e.total;
    db.get("SELECT COUNT(*) as total FROM attendance WHERE record_date = ?", [today], (err2, r2) => {
      result.todayRecords = r2?.total || 0;
      db.get("SELECT COUNT(*) as total FROM attendance WHERE strftime('%Y-%m', record_date)=strftime('%Y-%m','now')", [], (err3, m) => {
        result.monthRecords = m?.total || 0;
        res.json(result);
      });
    });
  });
});

app.get("/api/reports/daily", authenticateToken, (req, res) => {
  const { date } = req.query;
  if (!date) return res.status(400).json({ error: "Fecha requerida" });
  db.all(
    `SELECT a.*, e.first_name, e.last_name, e.employee_type FROM attendance a 
     JOIN employees e ON a.employee_id=e.id WHERE a.record_date=? ORDER BY a.record_time`,
    [date],
    (err, rows) => res.json(rows)
  );
});

app.get("/api/reports/weekly", authenticateToken, (req, res) => {
  const { start_date, end_date } = req.query;
  db.all(
    `SELECT a.*, e.first_name, e.last_name, e.employee_type FROM attendance a 
     JOIN employees e ON a.employee_id=e.id WHERE a.record_date BETWEEN ? AND ?`,
    [start_date, end_date],
    (err, rows) => res.json(rows)
  );
});

app.get("/api/reports/monthly", authenticateToken, (req, res) => {
  const { month } = req.query;
  db.all(
    `SELECT a.*, e.first_name, e.last_name, e.employee_type FROM attendance a 
     JOIN employees e ON a.employee_id=e.id WHERE strftime('%Y-%m', a.record_date)=?`,
    [month],
    (err, rows) => res.json(rows)
  );
});

app.get("/api/reports/employees-detailed", authenticateToken, (req, res) => {
  db.all(
    `SELECT e.*, COUNT(a.id) as total_records,
            SUM(CASE WHEN a.record_type='entrada' THEN 1 ELSE 0 END) as entradas,
            SUM(CASE WHEN a.record_type='salida' THEN 1 ELSE 0 END) as salidas
     FROM employees e
     LEFT JOIN attendance a ON e.id=a.employee_id
     GROUP BY e.id`,
    [],
    (err, rows) => res.json(rows)
  );
});

// ==========================
// 📊 DASHBOARD PRINCIPAL
// ==========================
app.get("/api/dashboard/stats", authenticateToken, (req, res) => {
  const today = new Date().toISOString().split("T")[0];
  const stats = {};
  db.get("SELECT COUNT(*) AS total FROM employees", [], (err, row) => {
    stats.total_employees = row.total;
    db.get("SELECT COUNT(*) AS total FROM attendance WHERE record_date = ?", [today], (err2, row2) => {
      stats.today_records = row2?.total || 0;
      db.get("SELECT COUNT(DISTINCT employee_id) AS total FROM attendance WHERE record_date = ?", [today], (err3, row3) => {
        stats.present_employees = row3?.total || 0;
        stats.absent_employees = Math.max(stats.total_employees - stats.present_employees, 0);
        res.json(stats);
      });
    });
  });
});

// ==========================
// 🚦 SALUD
// ==========================
app.get("/api/health", (req, res) => res.json({ status: "Servidor activo 🚀" }));

// ==========================
// 🚫 404
// ==========================
app.use((req, res) => res.status(404).json({ error: "Endpoint no encontrado" }));

app.listen(PORT, () => console.log(`🚀 Servidor corriendo en puerto ${PORT}`));
