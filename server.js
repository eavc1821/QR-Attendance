// ==========================
// 📦 IMPORTS Y CONFIGURACIÓN BASE
// ==========================
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const QRCode = require("qrcode");
const db = require("./database"); // conexión sqlite
const path = require("path");
const fs = require("fs");

// ==========================
// ⚙️ CONFIGURACIÓN DEL SERVIDOR
// ==========================
const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "asistencia_qr_secret_key_2024";
const BASE_URL = process.env.BASE_URL || "https://qr-attendance-production-27a2.up.railway.app";

app.use(cors({
  origin: '*', // o tu dominio de frontend si prefieres restringir
  credentials: true
}));

app.use(express.json({ limit: "10mb" }));

// ==========================
// 🔐 VERIFICACIÓN DE TOKEN (para restaurar sesión desde frontend)
// ==========================
app.get("/api/verify-token", (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    console.warn("❌ No se encontró el encabezado Authorization");
    return res.json({ valid: false });
  }

  const token = authHeader.split(" ")[1];
  try {
    jwt.verify(token, JWT_SECRET);
    console.log("✅ Token válido");
    res.json({ valid: true });
  } catch (err) {
    console.warn("⚠️ Token inválido o expirado:", err.message);
    res.json({ valid: false });
  }
});


// ==========================
// 📁 CONFIGURAR CARPETA DE UPLOADS
// ==========================
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

// ✅ Servir archivos estáticos (fotos y QRs)
app.use("/uploads", express.static(uploadsDir));



// ==========================
// 🔐 FUNCIONES AUXILIARES
// ==========================
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error("Token inválido:", err);
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
}

// ==========================
// 🧍 LOGIN DE USUARIO
// ==========================
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err) {
      console.error("Error buscando usuario:", err);
      return res.status(500).json({ error: "Error interno del servidor" });
    }
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: "Credenciales inválidas" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: "8h" }
    );

    res.json({
      message: "Login exitoso",
      token,
      user: { id: user.id, username: user.username, role: user.role, name: user.name },
    });
  });
});

// ==========================
// 👤 CREAR NUEVO EMPLEADO + QR
// ==========================
app.post("/api/employees", authenticateToken, (req, res) => {
  try {
    const { dni, first_name, last_name, employee_type, photo, salario_mensual } = req.body;

    if (!dni || !first_name || !last_name || !employee_type)
      return res.status(400).json({ error: "Todos los campos son requeridos" });

    if (!/^\d{13}$/.test(dni))
      return res.status(400).json({ error: "El DNI debe tener exactamente 13 dígitos" });

    if (employee_type === "Al Dia") {
      if (!salario_mensual && salario_mensual !== 0)
        return res.status(400).json({ error: "El salario mensual es requerido para empleados Al Dia" });
      const salario = parseFloat(salario_mensual);
      if (isNaN(salario) || salario < 0)
        return res.status(400).json({ error: "El salario mensual debe ser un número válido mayor o igual a 0" });
    }

    // 📦 Crear carpeta de QRs si no existe
    const qrDir = path.join(uploadsDir, "qrs");
    if (!fs.existsSync(qrDir)) fs.mkdirSync(qrDir, { recursive: true });

    const qrCodeData = `EMP-${dni}-${Date.now()}`;

    // 🖼️ Guardar foto si existe
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

    // 💾 Insertar empleado
    const insertData = [dni, first_name, last_name, employee_type, photoFilename, qrCodeData];
    let insertQuery = `
      INSERT INTO employees (dni, first_name, last_name, employee_type, photo, qr_code)
      VALUES (?, ?, ?, ?, ?, ?)
    `;

    if (employee_type === "Al Dia") {
      insertQuery = `
        INSERT INTO employees (dni, first_name, last_name, employee_type, photo, qr_code, salario_mensual)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `;
      insertData.push(parseFloat(salario_mensual));
    }

    db.run(insertQuery, insertData, function (err) {
      if (err) {
        console.error("Error al crear empleado:", err);
        if (err.message.includes("UNIQUE constraint failed"))
          return res.status(400).json({ error: "El DNI ya está registrado" });
        return res.status(500).json({ error: "Error al crear empleado" });
      }

      const employeeId = this.lastID;

      // 🧾 Generar y guardar QR físico
      const qrFilePath = path.join(qrDir, `employee_${employeeId}.png`);
      const qrPublicUrl = `${BASE_URL}/uploads/qrs/employee_${employeeId}.png`;

      QRCode.toFile(qrFilePath, qrCodeData, { width: 300 }, (qrErr) => {
        if (qrErr) {
          console.error("Error al generar QR:", qrErr);
          return res.status(500).json({ error: "Error al generar QR" });
        }

        // ✅ Guardar nombre del QR en DB
        db.run(
          "UPDATE employees SET qr_image = ? WHERE id = ?",
          [`employee_${employeeId}.png`, employeeId],
          (updateErr) => {
            if (updateErr) console.error("Error al guardar QR en DB:", updateErr);

            db.get("SELECT * FROM employees WHERE id = ?", [employeeId], (err, employee) => {
              if (err) {
                console.error("Error al obtener empleado creado:", err);
                return res.status(500).json({ error: "Error al obtener empleado creado" });
              }

              const employeeWithPhoto = {
                ...employee,
                photo_url: employee.photo ? `${BASE_URL}/uploads/${employee.photo}` : null,
                qr_url: qrPublicUrl,
              };

              res.status(201).json(employeeWithPhoto);
            });
          }
        );
      });
    });
  } catch (error) {
    console.error("Error en creación de empleado:", error);
    res.status(500).json({ error: "Error del servidor" });
  }
});

// ==========================
// 📋 OBTENER TODOS LOS EMPLEADOS
// ==========================
app.get("/api/employees", authenticateToken, (req, res) => {
  db.all("SELECT * FROM employees", [], (err, rows) => {
    if (err) {
      console.error("Error al obtener empleados:", err);
      return res.status(500).json({ error: "Error al obtener empleados" });
    }

    const employees = rows.map((e) => ({
      ...e,
      photo_url: e.photo ? `${BASE_URL}/uploads/${e.photo}` : null,
      qr_url: e.qr_image ? `${BASE_URL}/uploads/qrs/${e.qr_image}` : null,
    }));

    res.json(employees);
  });
});

// ==========================
// 🩺 HEALTH CHECK
// ==========================
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", message: "Servidor operativo" });
});

// ==========================
// 👥 RUTAS DE GESTIÓN DE USUARIOS
// ==========================

// 📋 Obtener todos los usuarios
app.get("/api/users", authenticateToken, (req, res) => {
  db.all("SELECT id, username, role, name, created_at FROM users", [], (err, rows) => {
    if (err) {
      console.error("Error al obtener usuarios:", err);
      return res.status(500).json({ error: "Error al obtener usuarios" });
    }
    res.json(rows);
  });
});

// ➕ Crear nuevo usuario
app.post("/api/users", authenticateToken, (req, res) => {
  const { username, password, role, name } = req.body;
  if (!username || !password || !role)
    return res.status(400).json({ error: "Todos los campos son requeridos" });

  const hashed = bcrypt.hashSync(password, 10);
  const createdAt = new Date().toISOString();

  db.run(
    "INSERT INTO users (username, password, role, name, created_at) VALUES (?, ?, ?, ?, ?)",
    [username, hashed, role, name || username, createdAt],
    function (err) {
      if (err) {
        console.error("Error creando usuario:", err);
        if (err.message.includes("UNIQUE constraint failed"))
          return res.status(400).json({ error: "El usuario ya existe" });
        return res.status(500).json({ error: "Error al crear usuario" });
      }
      res.status(201).json({ id: this.lastID, username, role, name, created_at: createdAt });
    }
  );
});

// ✏️ Actualizar usuario (nombre, rol o contraseña)
app.put("/api/users/:id", authenticateToken, (req, res) => {
  const { username, password, role, name } = req.body;
  const { id } = req.params;

  if (!username || !role)
    return res.status(400).json({ error: "Usuario y rol son requeridos" });

  db.get("SELECT * FROM users WHERE id = ?", [id], (err, user) => {
    if (err) return res.status(500).json({ error: "Error al buscar usuario" });
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    let query = "UPDATE users SET username = ?, role = ?, name = ? WHERE id = ?";
    let params = [username, role, name, id];

    if (password && password.trim() !== "") {
      const hashed = bcrypt.hashSync(password, 10);
      query = "UPDATE users SET username = ?, password = ?, role = ?, name = ? WHERE id = ?";
      params = [username, hashed, role, name, id];
    }

    db.run(query, params, function (updateErr) {
      if (updateErr) {
        console.error("Error actualizando usuario:", updateErr);
        return res.status(500).json({ error: "Error al actualizar usuario" });
      }
      res.json({ id, username, role, name });
    });
  });
});

// ❌ Eliminar usuario
app.delete("/api/users/:id", authenticateToken, (req, res) => {
  const { id } = req.params;

  db.get("SELECT * FROM users WHERE id = ?", [id], (err, user) => {
    if (err) return res.status(500).json({ error: "Error al buscar usuario" });
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    db.run("DELETE FROM users WHERE id = ?", [id], function (deleteErr) {
      if (deleteErr) {
        console.error("Error al eliminar usuario:", deleteErr);
        return res.status(500).json({ error: "Error al eliminar usuario" });
      }
      res.json({ message: "Usuario eliminado correctamente" });
    });
  });
});


// ==========================
// ⚠️ MANEJO DE RUTAS 404
// ==========================
app.use("/api/*", (req, res) => {
  console.log(`Ruta no encontrada: ${req.method} ${req.originalUrl}`);
  res.status(404).json({ error: "Endpoint no encontrado" });
});

// ==========================
// 🚀 INICIAR SERVIDOR
// ==========================
app.listen(PORT, () => {
  console.log(`✅ Servidor corriendo en puerto ${PORT}`);
  console.log(`🌐 BASE_URL: ${BASE_URL}`);
  console.log(`📊 Health check en /api/health`);
});
