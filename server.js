// ✅ Dependencias principales
import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import compression from "compression";
import QRCode from "qrcode";
import { initDatabase } from "./database.js";

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// ✅ Middlewares
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(compression());

let db;

// ✅ Inicializar base de datos modular
initDatabase()
  .then((database) => {
    db = database;
    app.locals.db = db;
    console.log("📦 Base de datos conectada correctamente");

    // 🔑 Middleware de autenticación
    function verifyToken(req, res, next) {
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) return res.status(403).json({ error: "Token no proporcionado" });

      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
      } catch (error) {
        return res.status(401).json({ error: "Token inválido o expirado" });
      }
    }

    function isSuperAdmin(req, res, next) {
      if (req.user?.role !== "superadmin") {
        return res.status(403).json({ error: "Acceso denegado: solo superadmin" });
      }
      next();
    }

    function isScanner(req, res, next) {
      if (req.user?.role !== "scanner" && req.user?.role !== "superadmin") {
        return res.status(403).json({ error: "Acceso denegado: solo scanner" });
      }
      next();
    }

    // 🧾 Login
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

        res.json({ token, role: user.role, name: user.name });
      } catch (err) {
        console.error("❌ Error en login:", err);
        res.status(500).json({ error: "Error en el servidor" });
      }
    });

    // 👥 CRUD Empleados (solo superadmin)
    app.get("/api/employees", verifyToken, isSuperAdmin, async (req, res) => {
      const empleados = await db.all("SELECT * FROM employees ORDER BY created_at DESC");
      res.json(empleados);
    });

    app.post("/api/employees", verifyToken, isSuperAdmin, async (req, res) => {
      try {
        const { dni, first_name, last_name, employee_type, salario_mensual } = req.body;
        const qrCode = `${dni}-${Date.now()}`;
        const qrImage = await QRCode.toDataURL(qrCode);

        await db.run(
          `INSERT INTO employees (dni, first_name, last_name, employee_type, salario_mensual, qr_code, qr_image)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [dni, first_name, last_name, employee_type, salario_mensual, qrCode, qrImage]
        );

        res.json({ success: true, message: "Empleado creado correctamente" });
      } catch (error) {
        console.error("❌ Error al crear empleado:", error);
        res.status(500).json({ error: "Error al crear empleado" });
      }
    });

    // 🕒 Asistencia (scanner y superadmin)
    app.post("/api/attendance/register", verifyToken, isScanner, async (req, res) => {
      try {
        const { employee_id, record_type, bags_elaborated, despalillo, escogida, moniado, horas_extras } = req.body;

        const fecha = new Date().toISOString().split("T")[0];
        const hora = new Date().toLocaleTimeString("es-HN", { hour12: false });

        await db.run(
          `INSERT INTO attendance (employee_id, record_type, record_date, record_time, bags_elaborated, despalillo, escogida, moniado, horas_extras)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)` ,
          [employee_id, record_type, fecha, hora, bags_elaborated, despalillo, escogida, moniado, horas_extras]
        );

        res.json({ success: true, message: "Registro de asistencia guardado" });
      } catch (error) {
        console.error("❌ Error al registrar asistencia:", error);
        res.status(500).json({ error: "Error al registrar asistencia" });
      }
    });

    // 📊 Obtener todas las asistencias (solo superadmin)
    app.get("/api/attendance", verifyToken, isSuperAdmin, async (req, res) => {
      try {
        const registros = await db.all(`
          SELECT a.id, e.first_name || ' ' || e.last_name AS empleado, 
                 a.record_type, a.record_date, a.record_time,
                 a.bags_elaborated, a.despalillo, a.escogida, a.moniado, a.horas_extras
          FROM attendance a
          JOIN employees e ON a.employee_id = e.id
          ORDER BY a.record_date DESC, a.record_time DESC
        `);
        res.json(registros);
      } catch (error) {
        console.error("❌ Error al obtener asistencias:", error);
        res.status(500).json({ error: "Error al obtener asistencias" });
      }
    });

    // 🧍‍♂️ Perfil actual
    app.get("/api/profile", verifyToken, async (req, res) => {
      const user = await db.get("SELECT id, username, name, role FROM users WHERE id = ?", [req.user.id]);
      res.json(user);
    });

    // 🚀 Iniciar servidor
    app.listen(PORT, () => {
      console.log(`✅ Servidor corriendo en puerto ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("❌ Error al iniciar base de datos:", err);
    process.exit(1);
  });
