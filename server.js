const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const QRCode = require('qrcode');
const db = require('./database');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'asistencia_qr_secret_key_2024';

// Crear directorio para uploads si no existe
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configuración CORS mejorada
// Configuración CORS mejorada - REEMPLAZA ESTA SECCIÓN
app.use(cors({
    origin: '*', // Temporalmente permitir todos los orígenes
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// O si prefieres mantener los orígenes específicos, agrega el puerto del frontend:
app.use(cors({
    origin: [
        'http://localhost:5173', 
        'http://127.0.0.1:5173',
        'http://localhost:3000',
        'http://localhost:5174' // Agregar este por si acaso
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Manejar preflight requests
app.options('*', cors());

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(uploadsDir));

// Middleware para logging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
});

// Middleware de autenticación
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token de acceso requerido' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido o expirado' });
        }
        req.user = user;
        next();
    });
};

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        service: 'Asistencia QR API'
    });
});

// Routes de autenticación
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        console.log('🔐 Intento de login para usuario:', username);

        if (!username || !password) {
            return res.status(400).json({ error: 'Usuario y contraseña son requeridos' });
        }

        // Convertir la consulta de la base de datos a promesa
        const user = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
                if (err) {
                    console.error('❌ Error en consulta de base de datos:', err);
                    reject(err);
                } else {
                    resolve(row);
                }
            });
        });

        console.log('👤 Usuario encontrado en BD:', user ? 'Sí' : 'No');

        if (!user) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        // Verificar contraseña
        const isValidPassword = await bcrypt.compare(password, user.password);
        console.log('🔑 Contraseña válida:', isValidPassword);

        if (!isValidPassword) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        // Generar token
        const token = jwt.sign(
            { 
                id: user.id, 
                username: user.username, 
                role: user.role 
            },
            JWT_SECRET,
            { expiresIn: '8h' }
        );

        console.log('✅ Login exitoso para:', user.username);

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                username: user.username,
                role: user.role,
                name: user.name
            }
        });

    } catch (error) {
        console.error('❌ Error general en login:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Routes de gestión de usuarios - SOLO SUPERADMIN
app.get('/api/users', authenticateToken, (req, res) => {
    // Verificar que sea superadmin
    if (req.user.role !== 'superadmin') {
        return res.status(403).json({ error: 'Se requieren privilegios de superadministrador' });
    }

    const query = 'SELECT id, username, role, name, created_at FROM users ORDER BY created_at DESC';
    
    db.all(query, (err, rows) => {
        if (err) {
            console.error('Error al obtener usuarios:', err);
            return res.status(500).json({ error: 'Error al obtener usuarios' });
        }
        res.json(rows || []);
    });
});

app.post('/api/users', authenticateToken, async (req, res) => {
    try {
        // Verificar que sea superadmin
        if (req.user.role !== 'superadmin') {
            return res.status(403).json({ error: 'Se requieren privilegios de superadministrador' });
        }

        const { username, password, role, name } = req.body;

        if (!username || !password || !role || !name) {
            return res.status(400).json({ error: 'Todos los campos son requeridos' });
        }

        // Validar roles permitidos
        if (!['superadmin', 'scanner'].includes(role)) {
            return res.status(400).json({ error: 'Rol no válido' });
        }

        // Hash de la contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        db.run(
            'INSERT INTO users (username, password, role, name) VALUES (?, ?, ?, ?)',
            [username, hashedPassword, role, name],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        return res.status(400).json({ error: 'El nombre de usuario ya existe' });
                    }
                    console.error('Error al crear usuario:', err);
                    return res.status(500).json({ error: 'Error al crear usuario' });
                }

                res.status(201).json({
                    id: this.lastID,
                    username,
                    role,
                    name,
                    created_at: new Date().toISOString()
                });
            }
        );
    } catch (error) {
        console.error('Error en creación de usuario:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
    try {
        // Verificar que sea superadmin
        if (req.user.role !== 'superadmin') {
            return res.status(403).json({ error: 'Se requieren privilegios de superadministrador' });
        }

        const { id } = req.params;
        const { username, password, role, name } = req.body;

        if (!username || !role || !name) {
            return res.status(400).json({ error: 'Usuario, rol y nombre son requeridos' });
        }

        // Validar roles permitidos
        if (!['superadmin', 'scanner'].includes(role)) {
            return res.status(400).json({ error: 'Rol no válido' });
        }

        let query;
        let params;

        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            query = 'UPDATE users SET username = ?, password = ?, role = ?, name = ? WHERE id = ?';
            params = [username, hashedPassword, role, name, id];
        } else {
            query = 'UPDATE users SET username = ?, role = ?, name = ? WHERE id = ?';
            params = [username, role, name, id];
        }

        db.run(query, params, function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(400).json({ error: 'El nombre de usuario ya existe' });
                }
                console.error('Error al actualizar usuario:', err);
                return res.status(500).json({ error: 'Error al actualizar usuario' });
            }

            if (this.changes === 0) {
                return res.status(404).json({ error: 'Usuario no encontrado' });
            }

            res.json({ message: 'Usuario actualizado correctamente' });
        });
    } catch (error) {
        console.error('Error en actualización de usuario:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

app.delete('/api/users/:id', authenticateToken, (req, res) => {
    // Verificar que sea superadmin
    if (req.user.role !== 'superadmin') {
        return res.status(403).json({ error: 'Se requieren privilegios de superadministrador' });
    }

    const { id } = req.params;

    // No permitir eliminar el propio usuario
    if (parseInt(id) === req.user.id) {
        return res.status(400).json({ error: 'No puedes eliminar tu propio usuario' });
    }

    db.run('DELETE FROM users WHERE id = ?', [id], function(err) {
        if (err) {
            console.error('Error al eliminar usuario:', err);
            return res.status(500).json({ error: 'Error al eliminar usuario' });
        }

        if (this.changes === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        res.json({ message: 'Usuario eliminado correctamente' });
    });
});


// Routes de empleados - CORREGIDAS
app.get('/api/employees', authenticateToken, (req, res) => {
    console.log('GET /api/employees - Obteniendo lista de empleados');
    
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

    db.all(query, (err, rows) => {
        if (err) {
            console.error('Error al obtener empleados:', err);
            return res.status(500).json({ error: 'Error al obtener empleados' });
        }
        
        console.log(`Encontrados ${rows ? rows.length : 0} empleados`);
        
        // Asegurar que siempre devolvemos un array
        const employees = Array.isArray(rows) ? rows : [];
        
        // Procesar foto para incluir URL completa
        const employeesWithPhoto = employees.map(employee => ({
            ...employee,
            photo_url: employee.photo ? `http://localhost:${PORT}/uploads/${employee.photo}` : null,
            is_present: Boolean(employee.is_present)
        }));
        
        res.json(employeesWithPhoto);
    });
});

//Creacion de Empleados
app.post('/api/employees', authenticateToken, async (req, res) => {
    try {
        console.log('POST /api/employees - Creando nuevo empleado:', req.body);
        
        const { dni, first_name, last_name, employee_type, photo, salario_mensual } = req.body; // NUEVO CAMPO

        if (!dni || !first_name || !last_name || !employee_type) {
            return res.status(400).json({ error: 'Todos los campos son requeridos' });
        }

        // Validar DNI
        if (!/^\d{13}$/.test(dni)) {
            return res.status(400).json({ error: 'El DNI debe tener exactamente 13 dígitos' });
        }

        // Validar salario mensual para empleados "Al Dia"
        if (employee_type === 'Al Dia') {
            if (!salario_mensual || salario_mensual === '') {
                return res.status(400).json({ error: 'El salario mensual es requerido para empleados Al Dia' });
            }
            
            const salario = parseFloat(salario_mensual);
            if (isNaN(salario) || salario < 0) {
                return res.status(400).json({ error: 'El salario mensual debe ser un número válido mayor o igual a 0' });
            }
        }

        // Generar código QR único
        const qrCodeData = `EMP-${dni}-${Date.now()}`;
        
        let photoFilename = null;
        if (photo) {
            // Guardar foto base64
            const matches = photo.match(/^data:image\/([A-Za-z-+/]+);base64,(.+)$/);
            if (matches) {
                const extension = matches[1] === 'jpeg' ? 'jpg' : matches[1];
                photoFilename = `employee_${Date.now()}.${extension}`;
                const photoBuffer = Buffer.from(matches[2], 'base64');
                fs.writeFileSync(path.join(uploadsDir, photoFilename), photoBuffer);
            }
        }

        // Preparar datos para inserción
        const insertData = [
            dni, first_name, last_name, employee_type, photoFilename, qrCodeData
        ];

        let insertQuery = `INSERT INTO employees (dni, first_name, last_name, employee_type, photo, qr_code) 
                          VALUES (?, ?, ?, ?, ?, ?)`;

        // Si es empleado Al Dia, agregar salario mensual
        if (employee_type === 'Al Dia') {
            insertQuery = `INSERT INTO employees (dni, first_name, last_name, employee_type, photo, qr_code, salario_mensual) 
                          VALUES (?, ?, ?, ?, ?, ?, ?)`;
            insertData.push(parseFloat(salario_mensual));
        }

        db.run(insertQuery, insertData, function(err) {
            if (err) {
                console.error('Error al crear empleado:', err);
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(400).json({ error: 'El DNI ya está registrado' });
                }
                return res.status(500).json({ error: 'Error al crear empleado' });
            }

            console.log('Empleado creado con ID:', this.lastID);

            // Obtener el empleado recién creado
            db.get('SELECT * FROM employees WHERE id = ?', [this.lastID], (err, employee) => {
                if (err) {
                    console.error('Error al obtener empleado creado:', err);
                    return res.status(500).json({ error: 'Error al obtener empleado creado' });
                }
                
                const employeeWithPhoto = {
                    ...employee,
                    photo_url: employee.photo ? `http://localhost:${PORT}/uploads/${employee.photo}` : null
                };
                
                res.status(201).json(employeeWithPhoto);
            });
        });
    } catch (error) {
        console.error('Error en creación de empleado:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// Nuevo endpoint para obtener empleados por tipo
app.get('/api/employees/type/:type', authenticateToken, (req, res) => {
    const { type } = req.params;
    
    console.log(`GET /api/employees/type/${type} - Obteniendo empleados por tipo`);
    
    if (type !== 'Al Dia' && type !== 'Tarea') {
        return res.status(400).json({ error: 'Tipo de empleado no válido' });
    }

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
            console.error('Error al obtener empleados por tipo:', err);
            return res.status(500).json({ error: 'Error al obtener empleados' });
        }
        
        console.log(`Encontrados ${rows ? rows.length : 0} empleados de tipo ${type}`);
        
        const employees = Array.isArray(rows) ? rows : [];
        
        const employeesWithPhoto = employees.map(employee => ({
            ...employee,
            photo_url: employee.photo ? `http://localhost:${PORT}/uploads/${employee.photo}` : null,
            is_present: Boolean(employee.is_present)
        }));
        
        res.json(employeesWithPhoto);
    });
});

//Actualizacion de Empleados
app.put('/api/employees/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { dni, first_name, last_name, employee_type, photo, salario_mensual } = req.body;

    console.log(`PUT /api/employees/${id} - Actualizando empleado`);

    if (!dni || !first_name || !last_name || !employee_type) {
        return res.status(400).json({ error: 'Todos los campos son requeridos' });
    }

    // Validar DNI
    if (!/^\d{13}$/.test(dni)) {
        return res.status(400).json({ error: 'El DNI debe tener exactamente 13 dígitos' });
    }

    // Validar salario mensual para empleados "Al Dia"
    if (employee_type === 'Al Dia') {
        if (!salario_mensual || salario_mensual === '') {
            return res.status(400).json({ error: 'El salario mensual es requerido para empleados Al Dia' });
        }
        
        const salario = parseFloat(salario_mensual);
        if (isNaN(salario) || salario < 0) {
            return res.status(400).json({ error: 'El salario mensual debe ser un número válido mayor o igual a 0' });
        }
    }

    let photoFilename = null;
    if (photo && photo.startsWith('data:image')) {
        // Guardar nueva foto base64
        const matches = photo.match(/^data:image\/([A-Za-z-+/]+);base64,(.+)$/);
        if (matches) {
            const extension = matches[1] === 'jpeg' ? 'jpg' : matches[1];
            photoFilename = `employee_${Date.now()}.${extension}`;
            const photoBuffer = Buffer.from(matches[2], 'base64');
            fs.writeFileSync(path.join(uploadsDir, photoFilename), photoBuffer);
        }
    }

    // Construir query dinámicamente
    let updateQuery = '';
    let params = [];

    if (photoFilename) {
        if (employee_type === 'Al Dia') {
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
        if (employee_type === 'Al Dia') {
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

    db.run(updateQuery, params, function(err) {
        if (err) {
            console.error('Error al actualizar empleado:', err);
            if (err.message.includes('UNIQUE constraint failed')) {
                return res.status(400).json({ error: 'El DNI ya está registrado' });
            }
            return res.status(500).json({ error: 'Error al actualizar empleado' });
        }

        if (this.changes === 0) {
            return res.status(404).json({ error: 'Empleado no encontrado' });
        }

        res.json({ message: 'Empleado actualizado correctamente' });
    });
});

app.delete('/api/employees/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    
    console.log(`DELETE /api/employees/${id} - Eliminando empleado`);

    db.run('UPDATE employees SET is_active = 0 WHERE id = ?', [id], function(err) {
        if (err) {
            console.error('Error al eliminar empleado:', err);
            return res.status(500).json({ error: 'Error al eliminar empleado' });
        }

        if (this.changes === 0) {
            return res.status(404).json({ error: 'Empleado no encontrado' });
        }

        res.json({ message: 'Empleado eliminado correctamente' });
    });
});

// Routes de asistencia
app.post('/api/attendance/scan', authenticateToken, (req, res) => {
    try {
        const { qr_code, bags_elaborated, despalillo, escogida, moniado, horas_extras } = req.body; // NUEVOS CAMPOS

        console.log('Solicitud de escaneo recibida:', { qr_code, bags_elaborated, despalillo, escogida, moniado, horas_extras });

        if (!qr_code) {
            return res.status(400).json({ error: 'Código QR requerido' });
        }

        // Buscar empleado por QR code
        db.get('SELECT * FROM employees WHERE qr_code = ? AND is_active = 1', [qr_code], (err, employee) => {
            if (err) {
                console.error('Error al buscar empleado:', err);
                return res.status(500).json({ error: 'Error del servidor al buscar empleado' });
            }

            if (!employee) {
                return res.status(404).json({ error: 'Código QR no válido o empleado inactivo' });
            }

            const now = new Date();
            const record_date = now.toISOString().split('T')[0];
            const record_time = now.toTimeString().split(' ')[0];

            console.log(`Procesando empleado: ${employee.first_name} ${employee.last_name}, Tipo: ${employee.employee_type}`);

            // Verificar si ya existe un registro completo (entrada y salida) para hoy
            db.get(`SELECT COUNT(*) as count FROM attendance 
                    WHERE employee_id = ? AND record_date = ?`,
                [employee.id, record_date],
                (err, result) => {
                    if (err) {
                        console.error('Error al verificar registros existentes:', err);
                        return res.status(500).json({ error: 'Error del servidor al verificar registros' });
                    }

                    // Si ya hay 2 registros (entrada y salida) para hoy, no permitir más
                    if (result.count >= 2) {
                        return res.status(400).json({ 
                            error: 'Ya se registró entrada y salida para hoy. No se pueden hacer más registros.' 
                        });
                    }

                    // Verificar último registro del día
                    db.get(`SELECT * FROM attendance 
                            WHERE employee_id = ? AND record_date = ? 
                            ORDER BY created_at DESC LIMIT 1`,
                        [employee.id, record_date],
                        (err, lastRecord) => {
                            if (err) {
                                console.error('Error al verificar último registro:', err);
                                return res.status(500).json({ error: 'Error del servidor al verificar último registro' });
                            }

                            let record_type = 'entry';
                            
                            // Si no hay registros hoy, es entrada
                            if (!lastRecord) {
                                record_type = 'entry';
                                console.log('Registrando ENTRADA - No hay registros previos hoy');
                            }
                            // Si el último registro fue entrada, ahora es salida
                            else if (lastRecord.record_type === 'entry') {
                                record_type = 'exit';
                                console.log('Registrando SALIDA - Último registro fue entrada');
                                
                                // Validar campos para empleados de tipo "Tarea"
                                if (employee.employee_type === 'Tarea') {
                                    console.log('Empleado es de Tarea, validando campos de producción...');
                                    
                                    // Validar que se envíen los campos de producción
                                    if (despalillo === undefined || despalillo === null || despalillo === '' ||
                                        escogida === undefined || escogida === null || escogida === '' ||
                                        moniado === undefined || moniado === null || moniado === '') { // NUEVA VALIDACIÓN
                                        return res.status(400).json({ 
                                            error: 'PRODUCTION_FIELDS_REQUIRED',
                                            message: 'Para empleados de tarea son requeridos los campos Despalillo, Escogida y Moñado al registrar salida'
                                        });
                                    }
                                    
                                    // Validar que sean números válidos
                                    const despalilloNum = parseInt(despalillo);
                                    const escogidaNum = parseInt(escogida);
                                    const moniadoNum = parseInt(moniado); // NUEVA VALIDACIÓN
                                    
                                    if (isNaN(despalilloNum) || despalilloNum < 0 || 
                                        isNaN(escogidaNum) || escogidaNum < 0 ||
                                        isNaN(moniadoNum) || moniadoNum < 0) { // NUEVA VALIDACIÓN
                                        return res.status(400).json({ 
                                            error: 'INVALID_PRODUCTION_FIELDS',
                                            message: 'Los campos Despalillo, Escogida y Moñado deben ser números válidos mayores o iguales a 0'
                                        });
                                    }
                                }
                                // Validar campo para empleados "Al Dia"
                                else if (employee.employee_type === 'Al Dia') {
                                    console.log('Empleado es Al Dia, validando campo horas extras...');
                                    
                                    // Validar que se envíe el campo horas_extras
                                    if (horas_extras === undefined || horas_extras === null || horas_extras === '') {
                                        return res.status(400).json({ 
                                            error: 'EXTRA_HOURS_REQUIRED',
                                            message: 'Para empleados Al Dia es requerido el campo Horas Extras al registrar salida'
                                        });
                                    }
                                    
                                    // Validar que sea un número válido
                                    const horasExtrasNum = parseInt(horas_extras);
                                    
                                    if (isNaN(horasExtrasNum) || horasExtrasNum < 0) {
                                        return res.status(400).json({ 
                                            error: 'INVALID_EXTRA_HOURS',
                                            message: 'El campo Horas Extras debe ser un número válido mayor o igual a 0'
                                        });
                                    }
                                }
                            }
                            // Si el último registro fue salida, no permitir otro registro
                            else if (lastRecord.record_type === 'exit') {
                                return res.status(400).json({ 
                                    error: 'Ya se registró salida para hoy. No se pueden hacer más registros.' 
                                });
                            }

                            // Preparar datos para inserción
                            const insertData = [
                                employee.id, 
                                record_type, 
                                record_date, 
                                record_time
                            ];

                            let insertQuery = `INSERT INTO attendance (employee_id, record_type, record_date, record_time) 
                                              VALUES (?, ?, ?, ?)`;

                            // Si es salida de empleado Tarea, agregar campos de producción
                            if (employee.employee_type === 'Tarea' && record_type === 'exit') {
                                insertQuery = `INSERT INTO attendance (employee_id, record_type, record_date, record_time, despalillo, escogida, moniado) 
                                              VALUES (?, ?, ?, ?, ?, ?, ?)`;
                                insertData.push(parseInt(despalillo), parseInt(escogida), parseInt(moniado));
                            }
                            // Si es salida de empleado Al Dia, agregar campo horas_extras
                            else if (employee.employee_type === 'Al Dia' && record_type === 'exit') {
                                insertQuery = `INSERT INTO attendance (employee_id, record_type, record_date, record_time, horas_extras) 
                                              VALUES (?, ?, ?, ?, ?)`;
                                insertData.push(parseInt(horas_extras));
                            }

                            console.log('Ejecutando query:', insertQuery);
                            console.log('Con parámetros:', insertData);

                            // Insertar nuevo registro
                            db.run(insertQuery, insertData, function(err) {
                                if (err) {
                                    console.error('Error al registrar asistencia:', err);
                                    return res.status(500).json({ error: 'Error al registrar asistencia en la base de datos' });
                                }

                                console.log('Registro exitoso. ID:', this.lastID);

                                const responseData = {
                                    success: true,
                                    message: `${record_type === 'entry' ? 'Entrada' : 'Salida'} registrada correctamente`,
                                    employee: {
                                        id: employee.id,
                                        name: `${employee.first_name} ${employee.last_name}`,
                                        type: employee.employee_type
                                    },
                                    record: {
                                        type: record_type,
                                        time: record_time,
                                        date: record_date
                                    }
                                };

                                // Agregar campos de producción si aplica
                                if (employee.employee_type === 'Tarea' && record_type === 'exit') {
                                    responseData.record.despalillo = parseInt(despalillo);
                                    responseData.record.escogida = parseInt(escogida);
                                    responseData.record.moniado = parseInt(moniado);
                                }
                                // Agregar campo horas extras si aplica
                                else if (employee.employee_type === 'Al Dia' && record_type === 'exit') {
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
        console.error('Error general en registro de asistencia:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.get('/api/attendance', authenticateToken, (req, res) => {
    try {
        const { date, employee_id, limit } = req.query;
        let query = `SELECT a.*, e.first_name, e.last_name, e.dni, e.employee_type
                     FROM attendance a
                     JOIN employees e ON a.employee_id = e.id
                     WHERE e.is_active = 1`;
        let params = [];

        if (date) {
            query += ' AND a.record_date = ?';
            params.push(date);
        }

        if (employee_id) {
            query += ' AND a.employee_id = ?';
            params.push(employee_id);
        }

        query += ' ORDER BY a.created_at DESC';

        if (limit) {
            query += ' LIMIT ?';
            params.push(parseInt(limit));
        }

        db.all(query, params, (err, rows) => {
            if (err) {
                console.error('Error al obtener registros:', err);
                return res.status(500).json({ error: 'Error al obtener registros' });
            }
            res.json(rows || []);
        });
    } catch (error) {
        console.error('Error en obtención de registros:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Generar código QR para empleado
app.get('/api/employees/:id/qr', authenticateToken, (req, res) => {
    const { id } = req.params;

    console.log(`GET /api/employees/${id}/qr - Generando QR`);

    db.get('SELECT qr_code FROM employees WHERE id = ? AND is_active = 1', [id], (err, employee) => {
        if (err) {
            console.error('Error al buscar empleado:', err);
            return res.status(500).json({ error: 'Error del servidor' });
        }

        if (!employee) {
            return res.status(404).json({ error: 'Empleado no encontrado' });
        }

        QRCode.toDataURL(employee.qr_code, (err, url) => {
            if (err) {
                console.error('Error al generar QR:', err);
                return res.status(500).json({ error: 'Error al generar código QR' });
            }
            res.json({ 
                qr_code: employee.qr_code, 
                qr_image: url 
            });
        });
    });
});

// Dashboard stats
app.get('/api/dashboard/stats', authenticateToken, (req, res) => {
    try {
        const today = new Date().toISOString().split('T')[0];

        db.get(`SELECT COUNT(*) as total_employees FROM employees WHERE is_active = 1`, (err, empResult) => {
            if (err) {
                console.error('Error en stats - empleados:', err);
                return res.status(500).json({ error: 'Error del servidor' });
            }

            db.get(`SELECT COUNT(*) as today_records FROM attendance WHERE record_date = ?`, [today], (err, attResult) => {
                if (err) {
                    console.error('Error en stats - registros:', err);
                    return res.status(500).json({ error: 'Error del servidor' });
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
                        console.error('Error en stats - presentes:', err);
                        return res.status(500).json({ error: 'Error del servidor' });
                    }

                    res.json({
                        total_employees: empResult.total_employees || 0,
                        today_records: attResult.today_records || 0,
                        present_employees: presentResult.present_employees || 0,
                        absent_employees: (empResult.total_employees || 0) - (presentResult.present_employees || 0)
                    });
                });
            });
        });
    } catch (error) {
        console.error('Error en dashboard stats:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Endpoints de reportes
// Endpoint para reporte diario - ACTUALIZADO
app.get('/api/reports/daily', authenticateToken, (req, res) => {
    const { date } = req.query;
    
    if (!date) {
        return res.status(400).json({ error: 'La fecha es requerida' });
    }

    const query = `
        SELECT a.*, e.first_name, e.last_name, e.dni, e.employee_type
        FROM attendance a
        JOIN employees e ON a.employee_id = e.id
        WHERE a.record_date = ? AND e.is_active = 1
        ORDER BY a.record_time DESC
    `;

    db.all(query, [date], (err, rows) => {
        if (err) {
            console.error('Error al obtener reporte diario:', err);
            return res.status(500).json({ error: 'Error al obtener reporte diario' });
        }
        res.json(rows || []);
    });
});

// Endpoint para reporte semanal - ACTUALIZADO
app.get('/api/reports/weekly', authenticateToken, (req, res) => {
    const { start_date, end_date } = req.query;
    
    if (!start_date || !end_date) {
        return res.status(400).json({ error: 'Las fechas de inicio y fin son requeridas' });
    }

    const query = `
        SELECT a.*, e.first_name, e.last_name, e.dni, e.employee_type, e.salario_mensual
        FROM attendance a
        JOIN employees e ON a.employee_id = e.id
        WHERE a.record_date BETWEEN ? AND ? AND e.is_active = 1
        ORDER BY e.employee_type, e.first_name, e.last_name, a.record_date DESC, a.record_time DESC
    `;

    db.all(query, [start_date, end_date], (err, rows) => {
        if (err) {
            console.error('Error al obtener reporte semanal:', err);
            return res.status(500).json({ error: 'Error al obtener reporte semanal' });
        }
        res.json(rows || []);
    });
});

// Endpoint para reporte mensual - ACTUALIZADO
app.get('/api/reports/monthly', authenticateToken, (req, res) => {
    const { month } = req.query;
    
    if (!month) {
        return res.status(400).json({ error: 'El mes es requerido (YYYY-MM)' });
    }

    const query = `
        SELECT a.*, e.first_name, e.last_name, e.dni, e.employee_type, e.salario_mensual
        FROM attendance a
        JOIN employees e ON a.employee_id = e.id
        WHERE strftime('%Y-%m', a.record_date) = ? AND e.is_active = 1
        ORDER BY e.employee_type, e.first_name, e.last_name, a.record_date DESC, a.record_time DESC
    `;

    db.all(query, [month], (err, rows) => {
        if (err) {
            console.error('Error al obtener reporte mensual:', err);
            return res.status(500).json({ error: 'Error al obtener reporte mensual' });
        }
        res.json(rows || []);
    });
});

// Endpoint para limpiar registros de asistencia
app.delete('/api/attendance/cleanup', authenticateToken, (req, res) => {
    // Verificar que solo superadmin pueda realizar esta acción
    if (req.user.role !== 'superadmin') {
        return res.status(403).json({ error: 'Solo los superadministradores pueden realizar esta acción' });
    }

    const { start_date, end_date, confirmation } = req.body;

    // Validar confirmación
    if (confirmation !== 'ELIMINAR_REGISTROS') {
        return res.status(400).json({ error: 'Se requiere confirmación para eliminar registros' });
    }

    let query = 'DELETE FROM attendance';
    let params = [];

    // Si se proporcionan fechas, eliminar solo en ese rango
    if (start_date && end_date) {
        query += ' WHERE record_date BETWEEN ? AND ?';
        params = [start_date, end_date];
    } else if (start_date) {
        query += ' WHERE record_date >= ?';
        params = [start_date];
    } else if (end_date) {
        query += ' WHERE record_date <= ?';
        params = [end_date];
    }
    // Si no se proporcionan fechas, eliminar todos los registros

    console.log(`Ejecutando limpieza de registros: ${query}`, params);

    db.run(query, params, function(err) {
        if (err) {
            console.error('Error al limpiar registros de asistencia:', err);
            return res.status(500).json({ error: 'Error al eliminar registros de asistencia' });
        }

        console.log(`Registros eliminados: ${this.changes}`);
        
        res.json({
            success: true,
            message: `Se eliminaron ${this.changes} registros de asistencia exitosamente`,
            records_deleted: this.changes
        });
    });
});

// Endpoint para obtener estadísticas de registros antes de la limpieza
app.get('/api/attendance/stats', authenticateToken, (req, res) => {
    const { start_date, end_date } = req.query;

    let dateCondition = '';
    let params = [];

    if (start_date && end_date) {
        dateCondition = 'WHERE record_date BETWEEN ? AND ?';
        params = [start_date, end_date];
    } else if (start_date) {
        dateCondition = 'WHERE record_date >= ?';
        params = [start_date];
    } else if (end_date) {
        dateCondition = 'WHERE record_date <= ?';
        params = [end_date];
    }

    const queries = {
        totalRecords: `SELECT COUNT(*) as count FROM attendance ${dateCondition}`,
        dateRange: `SELECT MIN(record_date) as min_date, MAX(record_date) as max_date FROM attendance ${dateCondition}`,
        recordsByType: `SELECT record_type, COUNT(*) as count FROM attendance ${dateCondition} GROUP BY record_type`,
        recordsByEmployeeType: `SELECT e.employee_type, COUNT(*) as count 
                               FROM attendance a 
                               JOIN employees e ON a.employee_id = e.id 
                               ${dateCondition ? dateCondition.replace('record_date', 'a.record_date') : ''} 
                               GROUP BY e.employee_type`
    };

    const results = {};

    const executeQuery = (queryKey, index) => {
        if (index >= Object.keys(queries).length) {
            // Todas las consultas completadas
            res.json(results);
            return;
        }

        const key = Object.keys(queries)[index];
        db.get(queries[key], params, (err, row) => {
            if (err) {
                console.error(`Error en consulta ${key}:`, err);
            } else {
                results[key] = row;
            }
            executeQuery(queryKey, index + 1);
        });
    };

    executeQuery('', 0);
});

// Endpoint para reporte de empleados (extendido) - ACTUALIZADO
// Eliminar cálculos relacionados con días ausentes
app.get('/api/reports/employees-detailed', authenticateToken, (req, res) => {
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
            console.error('Error al obtener reporte de empleados:', err);
            return res.status(500).json({ error: 'Error al obtener reporte de empleados' });
        }
        res.json(rows || []);
    });
});

app.get('/api/reports/quick-stats', authenticateToken, (req, res) => {
    const today = new Date().toISOString().split('T')[0];
    
    // Calcular inicio de la semana (lunes)
    const currentWeekStart = new Date();
    currentWeekStart.setDate(currentWeekStart.getDate() - currentWeekStart.getDay() + 1);
    const weekStart = currentWeekStart.toISOString().split('T')[0];
    
    const currentMonth = new Date().toISOString().substring(0, 7);

    // Ejecutar consultas en serie para evitar callbacks anidados
    const queries = [
        // Total empleados activos
        `SELECT COUNT(*) as total FROM employees WHERE is_active = 1`,
        
        // Empleados por tipo
        `SELECT employee_type, COUNT(*) as count FROM employees WHERE is_active = 1 GROUP BY employee_type`,
        
        // Registros hoy
        `SELECT COUNT(*) as today FROM attendance WHERE record_date = ?`,
        
        // Registros esta semana
        `SELECT COUNT(*) as week FROM attendance WHERE record_date BETWEEN ? AND ?`,
        
        // Registros este mes
        `SELECT COUNT(*) as month FROM attendance WHERE strftime('%Y-%m', record_date) = ?`,
        
        // Presentes hoy
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
         )`
    ];

    const results = {};

    // Función para ejecutar consultas en serie
    const executeQuery = (index) => {
        if (index >= queries.length) {
            // Todas las consultas completadas, enviar respuesta
            const totalEmployees = results.total || 0;
            const presentToday = results.present_today || 0;
            
            res.json({
                totalEmployees: totalEmployees,
                employeesByType: results.employeesByType || { 'Al Dia': 0, 'Tarea': 0 },
                todayRecords: results.today || 0,
                weekRecords: results.week || 0,
                monthRecords: results.month || 0,
                presentToday: presentToday,
                attendanceRate: totalEmployees > 0 ? ((presentToday / totalEmployees) * 100).toFixed(1) : 0,
                absenteeism: totalEmployees > 0 ? (100 - (presentToday / totalEmployees) * 100).toFixed(1) : 0,
                punctuality: 98 // Valor por defecto, podría calcularse
            });
            return;
        }

        const query = queries[index];
        let params = [];
        
        if (index === 2) params = [today]; // Registros hoy
        else if (index === 3) params = [weekStart, today]; // Registros semana
        else if (index === 4) params = [currentMonth]; // Registros mes
        else if (index === 5) params = [today]; // Presentes hoy

        db.get(query, params, (err, row) => {
            if (err) {
                console.error(`Error en consulta ${index}:`, err);
                // Continuar con la siguiente consulta incluso si hay error
            } else {
                if (index === 0) results.total = row.total;
                else if (index === 1) {
                    // Procesar empleados por tipo
                    db.all(queries[1], (err, rows) => {
                        if (!err && rows) {
                            results.employeesByType = rows.reduce((acc, row) => {
                                acc[row.employee_type] = row.count;
                                return acc;
                            }, {});
                        }
                        executeQuery(index + 1);
                    });
                    return; // Importante: return aquí para no ejecutar executeQuery dos veces
                }
                else if (index === 2) results.today = row.today;
                else if (index === 3) results.week = row.week;
                else if (index === 4) results.month = row.month;
                else if (index === 5) results.present_today = row.present_today;
            }
            
            if (index !== 1) { // Ya manejamos el índice 1 separadamente
                executeQuery(index + 1);
            }
        });
    };

    // Iniciar la ejecución de consultas
    executeQuery(0);
});

// Ruta simple para verificar que la base de datos tiene empleados
app.get('/api/debug/employees', authenticateToken, (req, res) => {
    db.all('SELECT id, dni, first_name, last_name FROM employees WHERE is_active = 1', (err, rows) => {
        if (err) {
            console.error('Error en debug employees:', err);
            return res.status(500).json({ error: 'Error del servidor' });
        }
        res.json({
            total: rows.length,
            employees: rows
        });
    });
});

// Manejo de errores 404 para API
app.use('/api/*', (req, res) => {
    console.log(`Ruta API no encontrada: ${req.method} ${req.originalUrl}`);
    res.status(404).json({ error: 'Endpoint API no encontrado' });
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Error no manejado:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
});

app.listen(PORT, () => {
    console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
    console.log(`👥 Employees API: http://localhost:${PORT}/api/employees`);
    console.log(`🔧 Debug Employees: http://localhost:${PORT}/api/debug/employees`);
});