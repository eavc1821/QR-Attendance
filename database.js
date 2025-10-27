import sqlite3 from "sqlite3";
import { open } from "sqlite";
import bcrypt from "bcryptjs";

/**
 * Inicializa la base de datos SQLite, crea las tablas necesarias
 * y asegura que exista un usuario superadmin por defecto.
 */
export async function initDatabase() {
  const db = await open({
    filename: "./database.sqlite",
    driver: sqlite3.Database,
  });

  // 🧱 Creación de tablas
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

  // 👑 Crear usuario superadmin si no existe
  const adminExists = await db.get("SELECT * FROM users WHERE username = 'admin'");
  if (!adminExists) {
    const hashedPassword = await bcrypt.hash("admin123", 10);
    await db.run(
      `INSERT INTO users (username, password, role, name)
       VALUES ('admin', ?, 'superadmin', 'Administrador General')`,
      [hashedPassword]
    );
    console.log("✅ Usuario superadmin creado: admin / admin123");
  }

  console.log("📦 Base de datos SQLite inicializada correctamente.");
  return db;
}
