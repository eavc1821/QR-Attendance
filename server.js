// ==========================
// 📦 DEPENDENCIAS
// ==========================
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const QRCode = require("qrcode");
const db = require("./database");
const path = require("path");
const fs = require("fs");

// ==========================
// ⚙️ CONFIGURACIÓN BASE
// ==========================
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "asistencia_qr_secret_key_2024";

// ==========================
// 🌐 VARIABLE GLOBAL BASE_URL
// ==========================
const BASE_URL = process.env.BASE_URL || ""; // Si está vacío, se genera dinámicamente con req

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
  "https://www.gjd78.com",
  "http://localhost:5173",
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true); // Permite Railway y Postman
      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("CORS bloqueado para origen: " + origin));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
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
// 👥 EJEMPLO RUTA EMPLEADOS
// ==========================
app.get("/api/employees", (req, res) => {
  db.all("SELECT * FROM employees", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });

    // Determinar URL base
    const baseUrl = BASE_URL || `${req.protocol}://${req.get("host")}`;

    const result = rows.map((emp) => ({
      ...emp,
      photo_url: emp.photo ? `${baseUrl}/uploads/${emp.photo}` : null,
    }));

    res.json(result);
  });
});

// ==========================
// 🧾 EJEMPLO RUTA ASISTENCIA
// ==========================
app.get("/api/attendance", authenticateToken, (req, res) => {
  db.all("SELECT * FROM attendance", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// ==========================
// 🧠 GENERACIÓN DE QR
// ==========================
app.post("/api/generate-qr", async (req, res) => {
  try {
    const { data } = req.body;
    if (!data) return res.status(400).json({ error: "Datos requeridos" });

    const qrPath = path.join(uploadsDir, `${Date.now()}.png`);
    await QRCode.toFile(qrPath, data);

    const baseUrl = BASE_URL || `${req.protocol}://${req.get("host")}`;
    const qrUrl = `${baseUrl}/uploads/${path.basename(qrPath)}`;

    res.json({ success: true, qrUrl });
  } catch (err) {
    console.error("Error al generar QR:", err);
    res.status(500).json({ error: "Error generando el QR" });
  }
});

app.get("/api/test", (req, res) => {
  res.json({ message: "✅ Ruta /api/test funcionando correctamente" });
});

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
  console.log(`🌐 Health check disponible en /api/health`);
});
