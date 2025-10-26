import sqlite3 from "sqlite3";
import { open } from "sqlite";
import path from "path";

let db;

// ===================================
// 💾 Inicialización robusta de SQLite
// ===================================
export async function initDatabase() {
  if (db) return db; // Evita reinicializaciones múltiples

  try {
    const dbPath = path.resolve("./asistencia.db");

    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });

    // Permite operaciones concurrentes sin bloqueo
    await db.exec("PRAGMA busy_timeout = 5000;");
    await db.exec("PRAGMA journal_mode = WAL;");
    await db.exec("PRAGMA foreign_keys = ON;");

    // Creación de tablas
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

    console.log("✅ Base de datos SQLite lista (asistencia.db)");

    return db;
  } catch (error) {
    console.error("❌ Error al inicializar la base de datos:", error);
    throw error;
  }
}

// ===================================
// 🔁 Función de reconexión automática
// ===================================
export async function getDatabase() {
  try {
    if (!db) {
      console.warn("⚠️ Base de datos no inicializada, reconectando...");
      await initDatabase();
    }
    return db;
  } catch (error) {
    console.error("❌ Error en conexión a base de datos:", error);
    throw error;
  }
}

// ===================================
// 🔧 Cierre limpio (opcional)
// ===================================
export async function closeDatabase() {
  if (db) {
    await db.close();
    db = null;
    console.log("🧹 Conexión SQLite cerrada correctamente");
  }
}
