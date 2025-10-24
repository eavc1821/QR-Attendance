// ==========================
// 📦 DEPENDENCIAS
// ==========================
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const QRCode = require("qrcode");
const db = require("./database"); // Asegúrate que ./database exporte la conexión sqlite
const path = require("path");
const fs = require("fs");

// ==========================
// ⚙️ CONFIGURACIÓN BASE
// ==========================
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "asistencia_qr_secret_key_2024";

// ==========================
// 🌐 URL BASE DE PRODUCCIÓN (fija)
// ==========================
const BASE_URL =
  process.env.BASE_URL || "https://qr-attendance-production-27a2.up.railway.app";

// ==========================
// 📁 CREAR DIRECTORIO UPLOADS
// ==========================
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// ==========================
// 🔒 CONFIGURACIÓN DE CORS
// ==========================
const allowedOrigins = [
  "https://gjd78.com",
  // si quieres incluir www, descomenta la siguiente línea:
  // "https://www.gjd78.com",
];

app.use(
  cors({
    origin: function (origin, callback) {
      // Permitir requests sin origin (Postman, curl, o internal requests)
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("CORS bloqueado para origen: " + origin));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  })
);

app.options("*", cors());

// ==========================
// 🧰 MIDDLEWARES
// ==========================
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use("/uploads", express.static(uploadsDir));

// Log básico
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} | ${req.method} ${req.path}`);
  next();
});

// ==========================
// 🚀 RUTA BASE Y HEALTH CHECK
// ==========================
app.get("/", (req, res) => {
  res.send("✅ Backend funcionando correctamente en Railway");
});

app.get("/api/health", (req, res) => {
  res.json({
    status: "OK",
    service: "Asistencia QR API",
    timestamp: new Date().toISOString(),
  });
});

// ==========================
// 🔑 AUTENTICACIÓN JWT
// ==========================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token requerido" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Token inválido o expirado" });
    req.user = user;
    next();
  });
};

// ==========================
// 🔐 LOGIN
// ==========================
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: "Usuario y contraseña requeridos" });

    const user = await new Promise((resolve, reject) => {
      db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (!user) return res.status(401).json({ error: "Credenciales inválidas" });

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).json({ error: "Credenciales inválidas" });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: "8h" }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        name: user.name,
      },
    });
  } catch (err) {
    console.error("Error en login:", err);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// ==========================
// 👥 RUTAS DE USUARIOS (ADMIN)
// ==========================
app.get("/api/users", authenticateToken, (req, res) => {
  if (req.user.role !== "superadmin")
    return res.status(403).json({ error: "Se requieren privilegios de superadministrador" });

  const query = "SELECT id, username, role, name, created_at FROM users ORDER BY created_at DESC";
  db.all(query, (err, rows) => {
    if (err) {
      console.error("Error al obtener usuarios:", err);
      return res.status(500).json({ error: "Error al obtener usuarios" });
    }
    res.json(rows || []);
  });
});

app.post("/api/users", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "superadmin")
      return res.status(403).json({ error: "Se requieren privilegios de superadministrador" });

    const { username, password, role, name } = req.body;
    if (!username || !password || !role || !name)
      return res.status(400).json({ error: "Todos los campos son requeridos" });

    if (!["superadmin", "scanner"].includes(role))
      return res.status(400).json({ error: "Rol no válido" });

    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
      "INSERT INTO users (username, password, role, name) VALUES (?, ?, ?, ?)",
      [username, hashedPassword, role, name],
      function (err) {
        if (err) {
          if (err.message.includes("UNIQUE constraint failed"))
            return res.status(400).json({ error: "El nombre de usuario ya existe" });
          console.error("Error al crear usuario:", err);
          return res.status(500).json({ error: "Error al crear usuario" });
        }
        res.status(201).json({
          id: this.lastID,
          username,
          role,
          name,
          created_at: new Date().toISOString(),
        });
      }
    );
  } catch (error) {
    console.error("Error en creación de usuario:", error);
    res.status(500).json({ error: "Error del servidor" });
  }
});

app.put("/api/users/:id", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "superadmin")
      return res.status(403).json({ error: "Se requieren privilegios de superadministrador" });

    const { id } = req.params;
    const { username, password, role, name } = req.body;
    if (!username || !role || !name)
      return res.status(400).json({ error: "Usuario, rol y nombre son requeridos" });

    if (!["superadmin", "scanner"].includes(role))
      return res.status(400).json({ error: "Rol no válido" });

    let query;
    let params;

    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      query = "UPDATE users SET username = ?, password = ?, role = ?, name = ? WHERE id = ?";
      params = [username, hashedPassword, role, name, id];
    } else {
      query = "UPDATE users SET username = ?, role = ?, name = ? WHERE id = ?";
      params = [username, role, name, id];
    }

    db.run(query, params, function (err) {
      if (err) {
        if (err.message.includes("UNIQUE constraint failed"))
          return res.status(400).json({ error: "El nombre de usuario ya existe" });
        console.error("Error al actualizar usuario:", err);
        return res.status(500).json({ error: "Error al actualizar usuario" });
      }
      if (this.changes === 0) return res.status(404).json({ error: "Usuario no encontrado" });
      res.json({ message: "Usuario actualizado correctamente" });
    });
  } catch (error) {
    console.error("Error en actualización de usuario:", error);
    res.status(500).json({ error: "Error del servidor" });
  }
});

app.delete("/api/users/:id", authenticateToken, (req, res) => {
  if (req.user.role !== "superadmin")
    return res.status(403).json({ error: "Se requieren privilegios de superadministrador" });

  const { id } = req.params;
  if (parseInt(id) === req.user.id)
    return res.status(400).json({ error: "No puedes eliminar tu propio usuario" });

  db.run("DELETE FROM users WHERE id = ?", [id], function (err) {
    if (err) {
      console.error("Error al eliminar usuario:", err);
      return res.status(500).json({ error: "Error al eliminar usuario" });
    }
    if (this.changes === 0) return res.status(404).json({ error: "Usuario no encontrado" });
    res.json({ message: "Usuario eliminado correctamente" });
  });
});

// ==========================
// 👥 RUTAS DE EMPLEADOS (CRUD + filtros)
// ==========================
app.get("/api/employees", authenticateToken, (req, res) => {
  const query = `
    SELECT e.*, 
           (SELECT COUNT(*) FROM attendance a 
            WHERE a.employee_id = e.id 
            AND a.record_date = date('now') 
            AND a.record_type = 'entry'
            AND NOT EXISTS (
                SELECT 1 FROM attendance a2 
                WHERE a2.employee_id = e.id 
                AND a2.record_date = a.record_date 
                AND a2.record_type = 'exit' 
                AND a2.created_at > a.created_at
            )) as is_present
    FROM employees e 
    WHERE e.is_active = 1 
    ORDER BY e.created_at DESC
  `;

  db.all(query, [], (err, rows) => {
    if (err) {
      console.error("Error al obtener empleados:", err);
      return res.status(500).json({ error: "Error al obtener empleados" });
    }

    const employees = Array.isArray(rows) ? rows : [];
    const employeesWithPhoto = employees.map((employee) => ({
      ...employee,
      photo_url: employee.photo ? `${BASE_URL}/uploads/${employee.photo}` : null,
      is_present: Boolean(employee.is_present),
    }));

    res.json(employeesWithPhoto);
  });
});

app.get("/api/employees/type/:type", authenticateToken, (req, res) => {
  const { type } = req.params;
  if (type !== "Al Dia" && type !== "Tarea")
    return res.status(400).json({ error: "Tipo de empleado no válido" });

  const query = `
    SELECT e.*, 
           (SELECT COUNT(*) FROM attendance a 
            WHERE a.employee_id = e.id 
            AND a.record_date = date('now') 
            AND a.record_type = 'entry'
            AND NOT EXISTS (
                SELECT 1 FROM attendance a2 
                WHERE a2.employee_id = e.id 
                AND a2.record_date = a.record_date 
                AND a2.record_type = 'exit' 
                AND a2.created_at > a.created_at
            )) as is_present
    FROM employees e 
    WHERE e.is_active = 1 
    AND e.employee_type = ?
    ORDER BY e.created_at DESC
  `;

  db.all(query, [type], (err, rows) => {
    if (err) {
      console.error("Error al obtener empleados por tipo:", err);
      return res.status(500).json({ error: "Error al obtener empleados" });
    }

    const employees = Array.isArray(rows) ? rows : [];
    const employeesWithPhoto = employees.map((employee) => ({
      ...employee,
      photo_url: employee.photo ? `${BASE_URL}/uploads/${employee.photo}` : null,
      is_present: Boolean(employee.is_present),
    }));

    res.json(employeesWithPhoto);
  });
});

app.post("/api/employees", authenticateToken, (req, res) => {
  try {
    const { dni, first_name, last_name, employee_type, photo, salario_mensual } = req.body;

    if (!dni || !first_name || !last_name || !employee_type)
      return res.status(400).json({ error: "Todos los campos son requeridos" });

    if (!/^\d{13}$/.test(dni)) return res.status(400).json({ error: "El DNI debe tener exactamente 13 dígitos" });

    if (employee_type === "Al Dia") {
      if (!salario_mensual && salario_mensual !== 0)
        return res.status(400).json({ error: "El salario mensual es requerido para empleados Al Dia" });
      const salario = parseFloat(salario_mensual);
      if (isNaN(salario) || salario < 0)
        return res.status(400).json({ error: "El salario mensual debe ser un número válido mayor o igual a 0" });
    }

    const qrCodeData = `EMP-${dni}-${Date.now()}`;

    let photoFilename = null;
    if (photo) {
      const matches = photo.match(/^data:image\/([A-Za-z-+/]+);base64,(.+)$/);
      if (matches) {
        const extension = matches[1] === "jpeg" ? "jpg" : matches[1];
        photoFilename = `employee_${Date.now()}.${extension}`;
        const photoBuffer = Buffer.from(matches[2], "base64");
        fs.writeFileSync(path.join(uploadsDir, photoFilename), photoBuffer);
      }
    }

    const insertData = [dni, first_name, last_name, employee_type, photoFilename, qrCodeData];
    let insertQuery = `INSERT INTO employees (dni, first_name, last_name, employee_type, photo, qr_code) VALUES (?, ?, ?, ?, ?, ?)`;

    if (employee_type === "Al Dia") {
      insertQuery = `INSERT INTO employees (dni, first_name, last_name, employee_type, photo, qr_code, salario_mensual) VALUES (?, ?, ?, ?, ?, ?, ?)`;
      insertData.push(parseFloat(salario_mensual));
    }

    db.run(insertQuery, insertData, function (err) {
      if (err) {
        console.error("Error al crear empleado:", err);
        if (err.message.includes("UNIQUE constraint failed"))
          return res.status(400).json({ error: "El DNI ya está registrado" });
        return res.status(500).json({ error: "Error al crear empleado" });
      }

      db.get("SELECT * FROM employees WHERE id = ?", [this.lastID], (err, employee) => {
        if (err) {
          console.error("Error al obtener empleado creado:", err);
          return res.status(500).json({ error: "Error al obtener empleado creado" });
        }
        const employeeWithPhoto = {
          ...employee,
          photo_url: employee.photo ? `${BASE_URL}/uploads/${employee.photo}` : null,
        };
        res.status(201).json(employeeWithPhoto);
      });
    });
  } catch (error) {
    console.error("Error en creación de empleado:", error);
    res.status(500).json({ error: "Error del servidor" });
  }
});

app.put("/api/employees/:id", authenticateToken, (req, res) => {
  try {
    const { id } = req.params;
    const { dni, first_name, last_name, employee_type, photo, salario_mensual } = req.body;

    if (!dni || !first_name || !last_name || !employee_type)
      return res.status(400).json({ error: "Todos los campos son requeridos" });

    if (!/^\d{13}$/.test(dni)) return res.status(400).json({ error: "El DNI debe tener exactamente 13 dígitos" });

    if (employee_type === "Al Dia") {
      if (!salario_mensual && salario_mensual !== 0)
        return res.status(400).json({ error: "El salario mensual es requerido para empleados Al Dia" });
      const salario = parseFloat(salario_mensual);
      if (isNaN(salario) || salario < 0)
        return res.status(400).json({ error: "El salario mensual debe ser un número válido mayor o igual a 0" });
    }

    let photoFilename = null;
    if (photo && photo.startsWith("data:image")) {
      const matches = photo.match(/^data:image\/([A-Za-z-+/]+);base64,(.+)$/);
      if (matches) {
        const extension = matches[1] === "jpeg" ? "jpg" : matches[1];
        photoFilename = `employee_${Date.now()}.${extension}`;
        const photoBuffer = Buffer.from(matches[2], "base64");
        fs.writeFileSync(path.join(uploadsDir, photoFilename), photoBuffer);
      }
    }

    let updateQuery = "";
    let params = [];

    if (photoFilename) {
      if (employee_type === "Al Dia") {
        updateQuery = `UPDATE employees 
                       SET dni = ?, first_name = ?, last_name = ?, employee_type = ?, photo = ?, salario_mensual = ?
                       WHERE id = ?`;
        params = [dni, first_name, last_name, employee_type, photoFilename, parseFloat(salario_mensual), id];
      } else {
        updateQuery = `UPDATE employees 
                       SET dni = ?, first_name = ?, last_name = ?, employee_type = ?, photo = ?, salario_mensual = NULL
                       WHERE id = ?`;
        params = [dni, first_name, last_name, employee_type, photoFilename, id];
      }
    } else {
      if (employee_type === "Al Dia") {
        updateQuery = `UPDATE employees 
                       SET dni = ?, first_name = ?, last_name = ?, employee_type = ?, salario_mensual = ?
                       WHERE id = ?`;
        params = [dni, first_name, last_name, employee_type, parseFloat(salario_mensual), id];
      } else {
        updateQuery = `UPDATE employees 
                       SET dni = ?, first_name = ?, last_name = ?, employee_type = ?, salario_mensual = NULL
                       WHERE id = ?`;
        params = [dni, first_name, last_name, employee_type, id];
      }
    }

    db.run(updateQuery, params, function (err) {
      if (err) {
        console.error("Error al actualizar empleado:", err);
        if (err.message.includes("UNIQUE constraint failed"))
          return res.status(400).json({ error: "El DNI ya está registrado" });
        return res.status(500).json({ error: "Error al actualizar empleado" });
      }

      if (this.changes === 0) return res.status(404).json({ error: "Empleado no encontrado" });
      res.json({ message: "Empleado actualizado correctamente" });
    });
  } catch (error) {
    console.error("Error en actualización de empleado:", error);
    res.status(500).json({ error: "Error del servidor" });
  }
});

app.delete("/api/employees/:id", authenticateToken, (req, res) => {
  const { id } = req.params;
  db.run("UPDATE employees SET is_active = 0 WHERE id = ?", [id], function (err) {
    if (err) {
      console.error("Error al eliminar empleado:", err);
      return res.status(500).json({ error: "Error al eliminar empleado" });
    }
    if (this.changes === 0) return res.status(404).json({ error: "Empleado no encontrado" });
    res.json({ message: "Empleado eliminado correctamente" });
  });
});

// ==========================
// 🧾 RUTAS DE ASISTENCIA (registro/consulta/limpieza/stats)
// ==========================
app.post("/api/attendance/scan", authenticateToken, (req, res) => {
  try {
    const { qr_code, bags_elaborated, despalillo, escogida, moniado, horas_extras } = req.body;
    if (!qr_code) return res.status(400).json({ error: "Código QR requerido" });

    db.get("SELECT * FROM employees WHERE qr_code = ? AND is_active = 1", [qr_code], (err, employee) => {
      if (err) {
        console.error("Error al buscar empleado:", err);
        return res.status(500).json({ error: "Error del servidor al buscar empleado" });
      }
      if (!employee) return res.status(404).json({ error: "Código QR no válido o empleado inactivo" });

      const now = new Date();
      const record_date = now.toISOString().split("T")[0];
      const record_time = now.toTimeString().split(" ")[0];

      // Verificar número de registros del día
      db.get(
        `SELECT COUNT(*) as count FROM attendance WHERE employee_id = ? AND record_date = ?`,
        [employee.id, record_date],
        (err, result) => {
          if (err) {
            console.error("Error al verificar registros existentes:", err);
            return res.status(500).json({ error: "Error del servidor al verificar registros" });
          }

          if (result.count >= 2) {
            return res.status(400).json({
              error: "Ya se registró entrada y salida para hoy. No se pueden hacer más registros.",
            });
          }

          db.get(
            `SELECT * FROM attendance WHERE employee_id = ? AND record_date = ? ORDER BY created_at DESC LIMIT 1`,
            [employee.id, record_date],
            (err, lastRecord) => {
              if (err) {
                console.error("Error al verificar último registro:", err);
                return res.status(500).json({ error: "Error del servidor al verificar último registro" });
              }

              let record_type = "entry";

              if (!lastRecord) {
                record_type = "entry";
              } else if (lastRecord.record_type === "entry") {
                record_type = "exit";

                if (employee.employee_type === "Tarea") {
                  if (
                    despalillo === undefined ||
                    despalillo === null ||
                    despalillo === "" ||
                    escogida === undefined ||
                    escogida === null ||
                    escogida === "" ||
                    moniado === undefined ||
                    moniado === null ||
                    moniado === ""
                  ) {
                    return res.status(400).json({
                      error: "PRODUCTION_FIELDS_REQUIRED",
                      message: "Para empleados de tarea son requeridos Despalillo, Escogida y Moñado al registrar salida",
                    });
                  }

                  const despalilloNum = parseInt(despalillo);
                  const escogidaNum = parseInt(escogida);
                  const moniadoNum = parseInt(moniado);

                  if (
                    isNaN(despalilloNum) ||
                    despalilloNum < 0 ||
                    isNaN(escogidaNum) ||
                    escogidaNum < 0 ||
                    isNaN(moniadoNum) ||
                    moniadoNum < 0
                  ) {
                    return res.status(400).json({
                      error: "INVALID_PRODUCTION_FIELDS",
                      message: "Los campos Despalillo, Escogida y Moñado deben ser números válidos >= 0",
                    });
                  }
                } else if (employee.employee_type === "Al Dia") {
                  if (horas_extras === undefined || horas_extras === null || horas_extras === "") {
                    return res.status(400).json({
                      error: "EXTRA_HOURS_REQUIRED",
                      message: "Para empleados Al Dia es requerido el campo Horas Extras al registrar salida",
                    });
                  }
                  const horasExtrasNum = parseInt(horas_extras);
                  if (isNaN(horasExtrasNum) || horasExtrasNum < 0) {
                    return res.status(400).json({
                      error: "INVALID_EXTRA_HOURS",
                      message: "El campo Horas Extras debe ser un número válido >= 0",
                    });
                  }
                }
              } else if (lastRecord.record_type === "exit") {
                return res.status(400).json({ error: "Ya se registró salida para hoy. No se pueden hacer más registros." });
              }

              const insertData = [employee.id, record_type, record_date, record_time];
              let insertQuery = `INSERT INTO attendance (employee_id, record_type, record_date, record_time) VALUES (?, ?, ?, ?)`;

              if (employee.employee_type === "Tarea" && record_type === "exit") {
                insertQuery = `INSERT INTO attendance (employee_id, record_type, record_date, record_time, despalillo, escogida, moniado) VALUES (?, ?, ?, ?, ?, ?, ?)`;
                insertData.push(parseInt(despalillo), parseInt(escogida), parseInt(moniado));
              } else if (employee.employee_type === "Al Dia" && record_type === "exit") {
                insertQuery = `INSERT INTO attendance (employee_id, record_type, record_date, record_time, horas_extras) VALUES (?, ?, ?, ?, ?)`;
                insertData.push(parseInt(horas_extras));
              }

              db.run(insertQuery, insertData, function (err) {
                if (err) {
                  console.error("Error al registrar asistencia:", err);
                  return res.status(500).json({ error: "Error al registrar asistencia en la base de datos" });
                }

                const responseData = {
                  success: true,
                  message: `${record_type === "entry" ? "Entrada" : "Salida"} registrada correctamente`,
                  employee: {
                    id: employee.id,
                    name: `${employee.first_name} ${employee.last_name}`,
                    type: employee.employee_type,
                  },
                  record: {
                    type: record_type,
                    time: record_time,
                    date: record_date,
                  },
                };

                if (employee.employee_type === "Tarea" && record_type === "exit") {
                  responseData.record.despalillo = parseInt(despalillo);
                  responseData.record.escogida = parseInt(escogida);
                  responseData.record.moniado = parseInt(moniado);
                } else if (employee.employee_type === "Al Dia" && record_type === "exit") {
                  responseData.record.horas_extras = parseInt(horas_extras);
                }

                res.json(responseData);
              });
            }
          );
        }
      );
    });
  } catch (error) {
    console.error("Error general en registro de asistencia:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

app.get("/api/attendance", authenticateToken, (req, res) => {
  try {
    const { date, employee_id, limit } = req.query;
    let query = `SELECT a.*, e.first_name, e.last_name, e.dni, e.employee_type
                 FROM attendance a
                 JOIN employees e ON a.employee_id = e.id
                 WHERE e.is_active = 1`;
    let params = [];

    if (date) {
      query += " AND a.record_date = ?";
      params.push(date);
    }

    if (employee_id) {
      query += " AND a.employee_id = ?";
      params.push(employee_id);
    }

    query += " ORDER BY a.created_at DESC";

    if (limit) {
      query += " LIMIT ?";
      params.push(parseInt(limit));
    }

    db.all(query, params, (err, rows) => {
      if (err) {
        console.error("Error al obtener registros:", err);
        return res.status(500).json({ error: "Error al obtener registros" });
      }
      res.json(rows || []);
    });
  } catch (error) {
    console.error("Error en obtención de registros:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// ==========================
// 🧾 ENDPOINTS DE REPORTES & DASHBOARD
// ==========================
app.get("/api/dashboard/stats", authenticateToken, (req, res) => {
  try {
    const today = new Date().toISOString().split("T")[0];

    db.get(`SELECT COUNT(*) as total_employees FROM employees WHERE is_active = 1`, (err, empResult) => {
      if (err) {
        console.error("Error en stats - empleados:", err);
        return res.status(500).json({ error: "Error del servidor" });
      }

      db.get(`SELECT COUNT(*) as today_records FROM attendance WHERE record_date = ?`, [today], (err, attResult) => {
        if (err) {
          console.error("Error en stats - registros:", err);
          return res.status(500).json({ error: "Error del servidor" });
        }

        db.get(`SELECT COUNT(DISTINCT a.employee_id) as present_employees
                FROM attendance a
                WHERE a.record_date = ? 
                AND a.record_type = 'entry'
                AND NOT EXISTS (
                    SELECT 1 FROM attendance a2 
                    WHERE a2.employee_id = a.employee_id 
                    AND a2.record_date = a.record_date 
                    AND a2.record_type = 'exit' 
                    AND a2.created_at > a.created_at
                )`, [today], (err, presentResult) => {
          if (err) {
            console.error("Error en stats - presentes:", err);
            return res.status(500).json({ error: "Error del servidor" });
          }

          res.json({
            total_employees: empResult.total_employees || 0,
            today_records: attResult.today_records || 0,
            present_employees: presentResult.present_employees || 0,
            absent_employees: (empResult.total_employees || 0) - (presentResult.present_employees || 0),
          });
        });
      });
    });
  } catch (error) {
    console.error("Error en dashboard stats:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// Reporte diario
app.get("/api/reports/daily", authenticateToken, (req, res) => {
  const { date } = req.query;
  if (!date) return res.status(400).json({ error: "La fecha es requerida" });

  const query = `
    SELECT a.*, e.first_name, e.last_name, e.dni, e.employee_type
    FROM attendance a
    JOIN employees e ON a.employee_id = e.id
    WHERE a.record_date = ? AND e.is_active = 1
    ORDER BY a.record_time DESC
  `;
  db.all(query, [date], (err, rows) => {
    if (err) {
      console.error("Error al obtener reporte diario:", err);
      return res.status(500).json({ error: "Error al obtener reporte diario" });
    }
    res.json(rows || []);
  });
});

// Reporte semanal
app.get("/api/reports/weekly", authenticateToken, (req, res) => {
  const { start_date, end_date } = req.query;
  if (!start_date || !end_date) return res.status(400).json({ error: "Las fechas de inicio y fin son requeridas" });

  const query = `
    SELECT a.*, e.first_name, e.last_name, e.dni, e.employee_type, e.salario_mensual
    FROM attendance a
    JOIN employees e ON a.employee_id = e.id
    WHERE a.record_date BETWEEN ? AND ? AND e.is_active = 1
    ORDER BY e.employee_type, e.first_name, e.last_name, a.record_date DESC, a.record_time DESC
  `;
  db.all(query, [start_date, end_date], (err, rows) => {
    if (err) {
      console.error("Error al obtener reporte semanal:", err);
      return res.status(500).json({ error: "Error al obtener reporte semanal" });
    }
    res.json(rows || []);
  });
});

// Reporte mensual
app.get("/api/reports/monthly", authenticateToken, (req, res) => {
  const { month } = req.query;
  if (!month) return res.status(400).json({ error: "El mes es requerido (YYYY-MM)" });

  const query = `
    SELECT a.*, e.first_name, e.last_name, e.dni, e.employee_type, e.salario_mensual
    FROM attendance a
    JOIN employees e ON a.employee_id = e.id
    WHERE strftime('%Y-%m', a.record_date) = ? AND e.is_active = 1
    ORDER BY e.employee_type, e.first_name, e.last_name, a.record_date DESC, a.record_time DESC
  `;
  db.all(query, [month], (err, rows) => {
    if (err) {
      console.error("Error al obtener reporte mensual:", err);
      return res.status(500).json({ error: "Error al obtener reporte mensual" });
    }
    res.json(rows || []);
  });
});

// Reporte empleados detallado
app.get("/api/reports/employees-detailed", authenticateToken, (req, res) => {
  const query = `
    SELECT e.*, 
           COUNT(DISTINCT a.record_date) as days_worked,
           COUNT(a.id) as total_records,
           SUM(CASE WHEN a.record_type = 'entry' THEN 1 ELSE 0 END) as total_entries,
           SUM(CASE WHEN a.record_type = 'exit' THEN 1 ELSE 0 END) as total_exits,
           SUM(CASE WHEN a.record_type = 'exit' THEN a.despalillo ELSE 0 END) as total_despalillo,
           SUM(CASE WHEN a.record_type = 'exit' THEN a.escogida ELSE 0 END) as total_escogida,
           SUM(CASE WHEN a.record_type = 'exit' THEN a.moniado ELSE 0 END) as total_moniado,
           SUM(CASE WHEN a.record_type = 'exit' THEN a.horas_extras ELSE 0 END) as total_horas_extras,
           AVG(CASE WHEN a.record_type = 'exit' THEN a.despalillo ELSE NULL END) as avg_despalillo,
           AVG(CASE WHEN a.record_type = 'exit' THEN a.escogida ELSE NULL END) as avg_escogida,
           AVG(CASE WHEN a.record_type = 'exit' THEN a.moniado ELSE NULL END) as avg_moniado,
           AVG(CASE WHEN a.record_type = 'exit' THEN a.horas_extras ELSE NULL END) as avg_horas_extras
    FROM employees e
    LEFT JOIN attendance a ON e.id = a.employee_id
    WHERE e.is_active = 1
    GROUP BY e.id
    ORDER BY e.created_at DESC
  `;
  db.all(query, (err, rows) => {
    if (err) {
      console.error("Error al obtener reporte de empleados:", err);
      return res.status(500).json({ error: "Error al obtener reporte de empleados" });
    }
    res.json(rows || []);
  });
});

// Quick stats
app.get("/api/reports/quick-stats", authenticateToken, (req, res) => {
  try {
    const today = new Date().toISOString().split("T")[0];

    const currentWeekStart = new Date();
    currentWeekStart.setDate(currentWeekStart.getDate() - currentWeekStart.getDay() + 1);
    const weekStart = currentWeekStart.toISOString().split("T")[0];

    const currentMonth = new Date().toISOString().substring(0, 7);

    const queries = [
      `SELECT COUNT(*) as total FROM employees WHERE is_active = 1`,
      `SELECT employee_type, COUNT(*) as count FROM employees WHERE is_active = 1 GROUP BY employee_type`,
      `SELECT COUNT(*) as today FROM attendance WHERE record_date = ?`,
      `SELECT COUNT(*) as week FROM attendance WHERE record_date BETWEEN ? AND ?`,
      `SELECT COUNT(*) as month FROM attendance WHERE strftime('%Y-%m', record_date) = ?`,
      `SELECT COUNT(DISTINCT a.employee_id) as present_today 
         FROM attendance a 
         WHERE a.record_date = ? 
         AND a.record_type = 'entry'
         AND NOT EXISTS (
             SELECT 1 FROM attendance a2 
             WHERE a2.employee_id = a.employee_id 
             AND a2.record_date = a.record_date 
             AND a2.record_type = 'exit' 
             AND a2.created_at > a.created_at
         )`,
    ];

    const results = {};

    const executeQuery = (index) => {
      if (index >= queries.length) {
        const totalEmployees = results.total || 0;
        const presentToday = results.present_today || 0;

        res.json({
          totalEmployees: totalEmployees,
          employeesByType: results.employeesByType || { "Al Dia": 0, "Tarea": 0 },
          todayRecords: results.today || 0,
          weekRecords: results.week || 0,
          monthRecords: results.month || 0,
          presentToday: presentToday,
          attendanceRate: totalEmployees > 0 ? ((presentToday / totalEmployees) * 100).toFixed(1) : 0,
          absenteeism: totalEmployees > 0 ? (100 - (presentToday / totalEmployees) * 100).toFixed(1) : 0,
          punctuality: 98,
        });
        return;
      }

      const query = queries[index];
      let params = [];

      if (index === 2) params = [today];
      else if (index === 3) params = [weekStart, today];
      else if (index === 4) params = [currentMonth];
      else if (index === 5) params = [today];

      if (index === 1) {
        db.all(query, [], (err, rows) => {
          if (!err && rows) {
            results.employeesByType = rows.reduce((acc, row) => {
              acc[row.employee_type] = row.count;
              return acc;
            }, {});
          }
          executeQuery(index + 1);
        });
        return;
      }

      db.get(query, params, (err, row) => {
        if (!err && row) {
          if (index === 0) results.total = row.total;
          else if (index === 2) results.today = row.today;
          else if (index === 3) results.week = row.week;
          else if (index === 4) results.month = row.month;
          else if (index === 5) results.present_today = row.present_today;
        }
        executeQuery(index + 1);
      });
    };

    executeQuery(0);
  } catch (error) {
    console.error("Error en quick-stats:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// ==========================
// 🧹 ENDPOINTS DE LIMPIEZA / STATS DE ASISTENCIA
// ==========================
app.delete("/api/attendance/cleanup", authenticateToken, (req, res) => {
  if (req.user.role !== "superadmin")
    return res.status(403).json({ error: "Solo los superadministradores pueden realizar esta acción" });

  const { start_date, end_date, confirmation } = req.body;
  if (confirmation !== "ELIMINAR_REGISTROS")
    return res.status(400).json({ error: "Se requiere confirmación para eliminar registros" });

  let query = "DELETE FROM attendance";
  let params = [];

  if (start_date && end_date) {
    query += " WHERE record_date BETWEEN ? AND ?";
    params = [start_date, end_date];
  } else if (start_date) {
    query += " WHERE record_date >= ?";
    params = [start_date];
  } else if (end_date) {
    query += " WHERE record_date <= ?";
    params = [end_date];
  }

  db.run(query, params, function (err) {
    if (err) {
      console.error("Error al limpiar registros de asistencia:", err);
      return res.status(500).json({ error: "Error al eliminar registros de asistencia" });
    }
    res.json({
      success: true,
      message: `Se eliminaron ${this.changes} registros de asistencia exitosamente`,
      records_deleted: this.changes,
    });
  });
});

// ==========================
// 🧹 LIMPIAR TODOS LOS EMPLEADOS (manteniendo usuarios intactos)
// ==========================
app.delete("/api/employees/cleanup", authenticateToken, (req, res) => {
  if (req.user.role !== "superadmin") {
    return res.status(403).json({ error: "Solo los superadministradores pueden realizar esta acción" });
  }

  const { confirmation } = req.body;
  if (confirmation !== "ELIMINAR_EMPLEADOS") {
    return res.status(400).json({
      error: "Se requiere confirmación para eliminar empleados. Usa { confirmation: 'ELIMINAR_EMPLEADOS' }",
    });
  }

  // Primero eliminar asistencias (dependientes)
  db.run("DELETE FROM attendance", [], function (err) {
    if (err) {
      console.error("Error al eliminar registros de asistencia:", err);
      return res.status(500).json({ error: "Error al eliminar registros de asistencia" });
    }

    // Luego eliminar empleados
    db.run("DELETE FROM employees", [], function (err2) {
      if (err2) {
        console.error("Error al eliminar empleados:", err2);
        return res.status(500).json({ error: "Error al eliminar empleados" });
      }

      res.json({
        success: true,
        message: `Se eliminaron todos los empleados y ${this.changes} registros de empleados.`,
        employees_deleted: this.changes,
      });
    });
  });
});


app.get("/api/attendance/stats", authenticateToken, (req, res) => {
  const { start_date, end_date } = req.query;

  let dateCondition = "";
  let params = [];

  if (start_date && end_date) {
    dateCondition = "WHERE record_date BETWEEN ? AND ?";
    params = [start_date, end_date];
  } else if (start_date) {
    dateCondition = "WHERE record_date >= ?";
    params = [start_date];
  } else if (end_date) {
    dateCondition = "WHERE record_date <= ?";
    params = [end_date];
  }

  const queries = {
    totalRecords: `SELECT COUNT(*) as count FROM attendance ${dateCondition}`,
    dateRange: `SELECT MIN(record_date) as min_date, MAX(record_date) as max_date FROM attendance ${dateCondition}`,
    recordsByType: `SELECT record_type, COUNT(*) as count FROM attendance ${dateCondition} GROUP BY record_type`,
    recordsByEmployeeType: `SELECT e.employee_type, COUNT(*) as count 
                           FROM attendance a 
                           JOIN employees e ON a.employee_id = e.id 
                           ${dateCondition ? dateCondition.replace("record_date", "a.record_date") : ""} 
                           GROUP BY e.employee_type`,
  };

  const results = {};

  const keys = Object.keys(queries);
  let idx = 0;

  const next = () => {
    if (idx >= keys.length) {
      return res.json(results);
    }
    const key = keys[idx++];
    db.get(queries[key], params, (err, row) => {
      if (err) {
        console.error(`Error en consulta ${key}:`, err);
        results[key] = null;
      } else {
        results[key] = row;
      }
      next();
    });
  };

  next();
});

// ==========================
// 🧪 RUTAS DE DEBUG
// ==========================
app.get("/api/test", (req, res) => {
  res.json({ ok: true, message: "API conectada correctamente 🚀" });
});

app.get("/api/debug/employees", authenticateToken, (req, res) => {
  db.all("SELECT id, dni, first_name, last_name FROM employees WHERE is_active = 1", (err, rows) => {
    if (err) {
      console.error("Error en debug employees:", err);
      return res.status(500).json({ error: "Error del servidor" });
    }
    res.json({ total: rows.length, employees: rows });
  });
});

// ==========================================================
// ⚙️ ENDPOINT TEMPORAL DE LIMPIEZA (mantiene usuarios y empleados)
// ==========================================================
app.delete("/api/cleanup", (req, res) => {
  const key = req.query.key;
  if (key !== "adminSecret123") {
    return res.status(403).json({ error: "Acceso no autorizado" });
  }

  console.log("🧹 Ejecutando limpieza de registros...");

  try {
    db.serialize(() => {
      db.run("DELETE FROM attendance", (err1) => {
        if (err1) {
          console.error("❌ Error al eliminar attendance:", err1);
          return res.status(500).json({ error: "Error al eliminar attendance" });
        }

        db.run("DELETE FROM production", (err2) => {
          if (err2) {
            console.error("❌ Error al eliminar production:", err2);
            return res.status(500).json({ error: "Error al eliminar production" });
          }

        db.run("DELETE FROM employees", (err2) => {
          if (err2) {
            console.error("❌ Error al eliminar empleados:", err2);
            return res.status(500).json({ error: "Error al eliminar empleados" });
          }
          

          console.log("✅ Registros de asistencia y producción eliminados correctamente.");
          res.json({
            success: true,
            message: "Registros de asistencia y producción eliminados correctamente.",
          });
        });
        });
      });
    });
  } catch (error) {
    console.error("Error al limpiar la base:", error);
    res.status(500).json({ error: "Error al limpiar los registros." });
  }
});

console.log("🚀 Endpoint /api/cleanup registrado correctamente");

// ==========================
// ⚠️ MANEJO DE 404 Y ERRORES
// ==========================
app.use("/api/*", (req, res) => {
  console.log(`Ruta no encontrada: ${req.method} ${req.originalUrl}`);
  res.status(404).json({ error: "Endpoint no encontrado" });
});

app.use((error, req, res, next) => {
  console.error("Error no manejado:", error);
  res.status(500).json({ error: "Error interno del servidor" });
});

// ==========================
// 🚀 INICIAR SERVIDOR
// ==========================
app.listen(PORT, () => {
  console.log(`✅ Servidor corriendo en puerto ${PORT}`);
  console.log(`🌐 BASE_URL: ${BASE_URL}`);
  console.log(`📊 Health check en /api/health`);
});

