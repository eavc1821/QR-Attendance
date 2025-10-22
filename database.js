const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

const dbPath = path.join(__dirname, 'asistencia.db');
const db = new sqlite3.Database(dbPath);

// Función para inicializar la base de datos
const initializeDatabase = () => {
    console.log('🔧 Inicializando base de datos...');
    
    // Crear tablas si no existen
    const tables = [
        `CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'scanner',
            name TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`,
        
        `CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dni TEXT UNIQUE NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            employee_type TEXT NOT NULL,
            photo TEXT,
            qr_code TEXT UNIQUE NOT NULL,
            salario_mensual DECIMAL(10,2) DEFAULT NULL,  -- NUEVA COLUMNA AGREGADA
            is_active BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`,
        
        `CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            record_type TEXT NOT NULL,
            record_date DATE NOT NULL,
            record_time TIME NOT NULL,
            bags_elaborated INTEGER DEFAULT NULL,
            despalillo INTEGER DEFAULT NULL,
            escogida INTEGER DEFAULT NULL,
            moniado INTEGER DEFAULT NULL,  -- NUEVA COLUMNA
            horas_extras INTEGER DEFAULT NULL,  -- NUEVA COLUMNA
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (employee_id) REFERENCES employees (id)
        )`
    ];

    // Ejecutar creación de tablas en serie
    const createTable = (index) => {
        if (index >= tables.length) {
            // Todas las tablas creadas, ahora insertar usuarios por defecto
            insertDefaultUsers();
            return;
        }
        
        db.run(tables[index], (err) => {
            if (err) {
                console.error(`Error creando tabla ${index + 1}:`, err);
            } else {
                console.log(`✅ Tabla ${index + 1} creada/verificada`);
            }
            createTable(index + 1);
        });
    };

    const insertDefaultUsers = () => {
        const hashedAdminPassword = bcrypt.hashSync('admin123', 10);
        const hashedScannerPassword = bcrypt.hashSync('scanner123', 10);
        
        const users = [
            ['admin', hashedAdminPassword, 'superadmin', 'Administrador Principal'],
            ['scanner', hashedScannerPassword, 'scanner', 'Operador Scanner']
        ];

        const insertUser = (index) => {
            if (index >= users.length) {
                // Todos los usuarios insertados, verificar columnas adicionales
                checkAdditionalColumns();
                return;
            }
            
            db.run(`INSERT OR IGNORE INTO users (username, password, role, name) VALUES (?, ?, ?, ?)`, 
                users[index], 
                (err) => {
                    if (err) {
                        console.error(`Error insertando usuario ${users[index][0]}:`, err);
                    } else {
                        console.log(`✅ Usuario ${users[index][0]} verificado`);
                    }
                    insertUser(index + 1);
                }
            );
        };

        insertUser(0);
    };

    const checkAdditionalColumns = () => {
        console.log('🔍 Verificando columnas adicionales...');
        
        // Verificar columnas en employees
        db.all(`PRAGMA table_info(employees)`, (err, rows) => {
            if (err) {
                console.error('Error al verificar estructura de employees:', err);
                return;
            }
            
            if (rows && Array.isArray(rows)) {
                const columnsToCheckEmployees = [
                    { name: 'salario_mensual', type: 'DECIMAL(10,2)' }
                ];
                
                columnsToCheckEmployees.forEach(column => {
                    const hasColumn = rows.some(row => row.name === column.name);
                    if (!hasColumn) {
                        addColumnToEmployees(column.name, column.type);
                    } else {
                        console.log(`✅ Columna ${column.name} ya existe en employees`);
                    }
                });
            } else {
                console.log('⚠️ No se pudieron obtener las columnas de employees');
            }
        });

        // Verificar columnas en attendance
        db.all(`PRAGMA table_info(attendance)`, (err, rows) => {
            if (err) {
                console.error('Error al verificar estructura de attendance:', err);
                return;
            }
            
            if (rows && Array.isArray(rows)) {
                const columnsToCheckAttendance = [
                    { name: 'moniado', type: 'INTEGER' },
                    { name: 'horas_extras', type: 'INTEGER' }
                ];
                
                columnsToCheckAttendance.forEach(column => {
                    const hasColumn = rows.some(row => row.name === column.name);
                    if (!hasColumn) {
                        addColumnToAttendance(column.name, column.type);
                    } else {
                        console.log(`✅ Columna ${column.name} ya existe en attendance`);
                    }
                });
            } else {
                console.log('⚠️ No se pudieron obtener las columnas de attendance');
            }
        });
    };

    const addColumnToEmployees = (columnName, columnType) => {
        console.log(`➕ Agregando columna ${columnName} a employees...`);
        db.run(`ALTER TABLE employees ADD COLUMN ${columnName} ${columnType} DEFAULT NULL`, (err) => {
            if (err) {
                if (err.message.includes('duplicate column name')) {
                    console.log(`✅ Columna ${columnName} ya existe en employees`);
                } else {
                    console.error(`❌ Error al agregar columna ${columnName} a employees:`, err);
                }
            } else {
                console.log(`✅ Columna ${columnName} agregada exitosamente a employees`);
            }
        });
    };

    const addColumnToAttendance = (columnName, columnType) => {
        console.log(`➕ Agregando columna ${columnName} a attendance...`);
        db.run(`ALTER TABLE attendance ADD COLUMN ${columnName} ${columnType} DEFAULT NULL`, (err) => {
            if (err) {
                if (err.message.includes('duplicate column name')) {
                    console.log(`✅ Columna ${columnName} ya existe en attendance`);
                } else {
                    console.error(`❌ Error al agregar columna ${columnName} a attendance:`, err);
                }
            } else {
                console.log(`✅ Columna ${columnName} agregada exitosamente a attendance`);
            }
        });
    };

    // Iniciar el proceso
    createTable(0);
};

// Inicializar la base de datos
initializeDatabase();

module.exports = db;