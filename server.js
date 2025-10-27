// server_postgres.js
import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import compression from "compression";
import QRCode from "qrcode";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { Sequelize, DataTypes } from "sequelize";

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// 🧩 Rutas absolutas del proyecto
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ✅ Middlewares


const allowedOrigins = [
  "http://localhost:5173",   // entorno local (vite)
  "https://gjd78.com",       // tu dominio en producción
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.header("Access-Control-Allow-Origin", origin);
  }

  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization"
  );
  res.header("Access-Control-Allow-Credentials", "true");

  // Manejar preflight (OPTIONS)
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }

  next();
});

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ limit: "10mb", extended: true }));
app.use(compression());

// 📁 Servir imágenes estáticas
app.use("/uploads", express.static(path.join(__dirname, "public", "uploads")));
app.use("/qrcodes", express.static(path.join(__dirname, "public", "qrcodes")));

// ✅ Conexión a PostgreSQL
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error("❌ FALTA la variable DATABASE_URL en Railway");
  process.exit(1);
}

const sequelize = new Sequelize(DATABASE_URL, {
  dialect: "postgres",
  dialectOptions: {
    ssl: { require: true, rejectUnauthorized: false },
  },
  logging: false,
  pool: { max: 15, min: 5, acquire: 30000, idle: 10000 },
});

// ✅ Modelos
const User = sequelize.define("User", {
  username: { type: DataTypes.STRING, unique: true, allowNull: false },
  password: { type: DataTypes.STRING, allowNull: false },
  role: { type: DataTypes.STRING, defaultValue: "scanner" },
  name: { type: DataTypes.STRING, allowNull: false },
});

const Employee = sequelize.define("Employee", {
  dni: { type: DataTypes.STRING, unique: true, allowNull: false },
  first_name: { type: DataTypes.STRING, allowNull: false },
  last_name: { type: DataTypes.STRING, allowNull: false },
  employee_type: { type: DataTypes.STRING, allowNull: false },
  salario_mensual: DataTypes.DECIMAL(10, 2),
  qr_code: { type: DataTypes.STRING, unique: true },
  qr_image: DataTypes.TEXT,
  photo: DataTypes.TEXT,
  is_active: { type: DataTypes.BOOLEAN, defaultValue: true },
});

const Attendance = sequelize.define("Attendance", {
  record_type: DataTypes.STRING,
  record_date: DataTypes.DATEONLY,
  record_time: DataTypes.TIME,
  bags_elaborated: DataTypes.INTEGER,
  despalillo: DataTypes.INTEGER,
  escogida: DataTypes.INTEGER,
  moniado: DataTypes.INTEGER,
  horas_extras: DataTypes.INTEGER,
});

// 🔗 Relaciones
Employee.hasMany(Attendance, { foreignKey: "employee_id" });
Attendance.belongsTo(Employee, { foreignKey: "employee_id" });

// 🧠 Inicialización
const initDB = async () => {
  try {
    await sequelize.authenticate();
    console.log("✅ Conectado a PostgreSQL");

    await sequelize.sync(); // ❗ No borra datos ni reinicia tablas
    console.log("🧩 Tablas sincronizadas correctamente");

    // Índices
    await sequelize.query(
      'CREATE INDEX IF NOT EXISTS idx_employees_dni ON "Employees" (dni);'
    );
    await sequelize.query(
      'CREATE INDEX IF NOT EXISTS idx_attendance_date ON "Attendances" (record_date);'
    );

    // Crear superadmin si no existe
    const admin = await User.findOne({ where: { username: "admin" } });
    if (!admin) {
      const hashed = await bcrypt.hash("admin123", 10);
      await User.create({
        username: "admin",
        password: hashed,
        role: "superadmin",
        name: "Administrador General",
      });
      console.log("👑 Superadmin creado (admin / admin123)");
    }
  } catch (err) {
    console.error("❌ Error al iniciar la base de datos:", err);
    process.exit(1);
  }
};

// 🛡️ Middleware de autenticación
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
    const user = await User.findOne({ where: { username } });
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
    res.status(500).json({ error: "Error en login" });
  }
});

// 👥 CRUD de usuarios
app.get("/api/users", authenticate, async (req, res) => {
  if (req.user.role !== "superadmin")
    return res.status(403).json({ error: "Acceso denegado" });
  const users = await User.findAll({
    attributes: ["id", "username", "role", "name", "createdAt"],
  });
  res.json(users);
});

app.post("/api/users", authenticate, async (req, res) => {
  if (req.user.role !== "superadmin")
    return res.status(403).json({ error: "Acceso denegado" });
  const { username, password, role, name } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  await User.create({ username, password: hashed, role, name });
  res.json({ message: "Usuario creado correctamente" });
});

app.put("/api/users/:id", authenticate, async (req, res) => {
  if (req.user.role !== "superadmin")
    return res.status(403).json({ error: "Acceso denegado" });
  const { id } = req.params;
  const { username, password, role, name } = req.body;

  const updateData = { username, role, name };
  if (password) updateData.password = await bcrypt.hash(password, 10);

  await User.update(updateData, { where: { id } });
  res.json({ message: "Usuario actualizado correctamente" });
});

app.delete("/api/users/:id", authenticate, async (req, res) => {
  if (req.user.role !== "superadmin")
    return res.status(403).json({ error: "Acceso denegado" });
  const { id } = req.params;
  await User.destroy({ where: { id } });
  res.json({ message: "Usuario eliminado correctamente" });
});

// 👥 CRUD de empleados
app.get("/api/employees", authenticate, async (req, res) => {
  const employees = await Employee.findAll({ where: { is_active: true } });
  res.json(employees);
});

app.post("/api/employees", authenticate, async (req, res) => {
  try {
    const { dni, first_name, last_name, employee_type, salario_mensual, photo } = req.body;

    const qr_code = `${dni}-${Date.now()}`;
    const qrDir = path.join(__dirname, "public", "qrcodes");
    if (!fs.existsSync(qrDir)) fs.mkdirSync(qrDir, { recursive: true });

    const qrPath = path.join(qrDir, `${qr_code}.png`);
    await QRCode.toFile(qrPath, qr_code);
    const qr_url = `/qrcodes/${qr_code}.png`;

    // Guardar imagen si se envía
    let photo_url = null;
    if (photo) {
      const uploadDir = path.join(__dirname, "public", "uploads");
      if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

      const base64Data = photo.replace(/^data:image\/\w+;base64,/, "");
      const photoPath = path.join(uploadDir, `${dni}.png`);
      fs.writeFileSync(photoPath, Buffer.from(base64Data, "base64"));
      photo_url = `/uploads/${dni}.png`;
    }

    await Employee.create({
      dni,
      first_name,
      last_name,
      employee_type,
      salario_mensual,
      qr_code,
      qr_image: qr_url,
      photo: photo_url,
    });

    res.json({
      message: "Empleado registrado correctamente",
      qr_url,
      photo_url,
    });
  } catch (err) {
    console.error("❌ Error al registrar empleado:", err);
    res.status(500).json({ error: "Error registrando empleado" });
  }
});

// 📅 Registros de asistencia
app.get("/api/attendance", authenticate, async (req, res) => {
  const records = await Attendance.findAll({
    include: [{ model: Employee, attributes: ["first_name", "last_name"] }],
    order: [["createdAt", "DESC"]],
  });
  res.json(records);
});

// 📊 Dashboard
app.get("/api/dashboard/stats", authenticate, async (req, res) => {
  const totalEmployees = await Employee.count({ where: { is_active: true } });
  const totalRecords = await Attendance.count();
  const todayRecords = await Attendance.count({
    where: sequelize.where(
      sequelize.fn("DATE", sequelize.col("record_date")),
      "=",
      sequelize.literal("CURRENT_DATE")
    ),
  });

  res.json({
    totalEmployees,
    totalRecords,
    todayRecords,
  });
});

// ✅ Verificar token
app.get("/api/verify-token", async (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.json({ valid: false });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findByPk(decoded.id, {
      attributes: ["id", "username", "role", "name"],
    });
    if (!user) return res.json({ valid: false });
    res.json({ valid: true, user });
  } catch {
    res.json({ valid: false });
  }
});

// 🚀 Iniciar servidor
initDB().then(() =>
  app.listen(PORT, () => console.log(`✅ Servidor en puerto ${PORT}`))
);
