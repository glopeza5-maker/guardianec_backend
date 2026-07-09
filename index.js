const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));


const dbPool = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'Gabriel2000',
  database: process.env.DB_NAME || 'guardianec_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: {
    rejectUnauthorized: false
  }
});


dbPool.getConnection((err, connection) => {
  if (err) {
    console.error('❌ Error de conexión con Aiven:', err.message);
    console.log('⚠️ El servidor seguirá corriendo y reintentará en la próxima petición.');
    return;
  }
  
  console.log('☑ ¡Conectado exitosamente al Pool de Aiven (GuardianEC)!');

  const crearTablaUsuarios = `
    CREATE TABLE IF NOT EXISTS usuarios (
      id INT AUTO_INCREMENT PRIMARY KEY,
      nombre VARCHAR(100) NOT NULL,
      email VARCHAR(100) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`;

  const crearTablaIncidentes = `
    CREATE TABLE IF NOT EXISTS incidentes (
      id INT AUTO_INCREMENT PRIMARY KEY,
      usuario_id INT NOT NULL,
      titulo VARCHAR(150) NOT NULL,
      descripcion TEXT,
      latitud DOUBLE NOT NULL,
      longitud DOUBLE NOT NULL,
      categoria VARCHAR(50) NOT NULL,
      estado VARCHAR(20) DEFAULT 'Pendiente',
      imagen_base64 LONGTEXT,
      fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
    );`;

  
  const crearTablaValidaciones = `
    CREATE TABLE IF NOT EXISTS validaciones (
      id INT AUTO_INCREMENT PRIMARY KEY,
      incidente_id INT NOT NULL,
      usuario_id INT NOT NULL,
      fecha_voto TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY voto_unico (incidente_id, usuario_id),
      FOREIGN KEY (incidente_id) REFERENCES incidentes(id) ON DELETE CASCADE,
      FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
    );`;

  connection.query(crearTablaUsuarios, (err) => {
    if (err) console.error("Error al crear tabla usuarios:", err.message);
    connection.query(crearTablaIncidentes, (err) => {
      if (err) console.error("Error al crear tabla incidentes:", err.message);
      connection.query(crearTablaValidaciones, (err) => {
        if (err) console.error("Error al crear tabla validaciones:", err.message);
        console.log("🚀 Tablas (Usuarios, Incidentes y Validaciones) sincronizadas en Aiven.");
        connection.release(); // Liberar la conexión al pool
      });
    });
  });
});

const JWT_SECRET = 'clave_secreta_guardianec_2026';

function verificarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(403).json({ error: 'Acceso denegado. Token no provisto.' });
  }

  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Sesión expirada o token inválido.' });
    }
    req.usuarioId = decoded.id; 
    next(); 
  });
}


app.post('/api/usuarios/registro', async (req, res) => {
  const { nombre, email, password } = req.body;
  if (!nombre || !email || !password) return res.status(400).json({ error: 'Todos los campos son obligatorios.' });

  try {
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    const query = 'INSERT INTO usuarios (nombre, email, password_hash) VALUES (?, ?, ?)';
    dbPool.query(query, [nombre, email, passwordHash], (err, result) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'El correo electrónico ya está registrado.' });
        return res.status(500).json({ error: `Error en base de datos: ${err.message}` });
      }
      res.status(201).json({ mensaje: '¡Usuario registrado exitosamente!' });
    });
  } catch (e) {
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});


app.post('/api/usuarios/login', (req, res) => {
  const { email, password } = req.body;
  dbPool.query('SELECT * FROM usuarios WHERE email = ?', [email], async (err, results) => {
    if (err || results.length === 0) return res.status(400).json({ error: 'Credenciales incorrectas.' });
    const usuario = results[0];
    const passwordCorrecto = await bcrypt.compare(password, usuario.password_hash);
    if (!passwordCorrecto) return res.status(400).json({ error: 'Credenciales incorrectas.' });

    const token = jwt.sign({ id: usuario.id, email: usuario.email }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ mensaje: '¡Bienvenido!', token, usuario: { id: usuario.id, nombre: usuario.nombre } });
  });
});


app.get('/api/incidentes/listar', (req, res) => {
  const query = `
    SELECT i.*, u.nombre as reportero, 
      (SELECT COUNT(*) FROM validaciones v WHERE v.incidente_id = i.id) as votos 
    FROM incidentes i 
    JOIN usuarios u ON i.usuario_id = u.id 
    ORDER BY i.fecha_creacion DESC`;
    
  dbPool.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Error al cargar incidentes.' });
    res.json(results);
  });
});


app.post('/api/incidentes/crear', verificarToken, (req, res) => {
  const { titulo, descripcion, latitud, longitud, categoria, imagen_base64 } = req.body;
  const usuario_id = req.usuarioId; 
  const lat_num = parseFloat(latitud);
  const lon_num = parseFloat(longitud);

  if (!usuario_id) {
    return res.status(400).json({ error: 'No se pudo identificar al usuario. Inicia sesión nuevamente.' });
  }

  const queryInsertar = 'INSERT INTO incidentes (usuario_id, titulo, descripcion, latitud, longitud, categoria, estado, imagen_base64) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
  
  dbPool.query(
    queryInsertar, 
    [usuario_id, titulo, descripcion || '', lat_num, lon_num, categoria, 'Pendiente', imagen_base64 || null], 
    (errInsert, result) => {
      if (errInsert) {
        return res.status(500).json({ error: `MySQL Falló: ${errInsert.message}` });
      }
      res.status(201).json({ mensaje: '¡Incidente reportado!', incidenteId: result.insertId });
    }
  );
});


app.put('/api/incidentes/resolver/:id', verificarToken, (req, res) => {
  const incidenteId = req.params.id;
  const usuarioQueVota = req.usuarioId;

  // 1. Buscamos el incidente en la base de datos
  dbPool.query("SELECT usuario_id, estado FROM incidentes WHERE id = ?", [incidenteId], (errBuscar, results) => {
    if (errBuscar || results.length === 0) return res.status(404).json({ error: 'Incidente no encontrado.' });
    
    const incidente = results[0];
    if (incidente.estado === 'Resuelto') {
      return res.json({ resuelto: true, estado: 'Resuelto', mensaje: 'Este incidente ya fue solucionado.' });
    }

    
    if (incidente.usuario_id === usuarioQueVota) {
      dbPool.query("UPDATE incidentes SET estado = 'Resuelto' WHERE id = ?", [incidenteId], (errUpdate) => {
        if (errUpdate) return res.status(500).json({ error: errUpdate.message });
        return res.json({ 
          resuelto: true, 
          estado: 'Resuelto', 
          votos: 2, 
          mensaje: '¡Incidente cerrado por el autor original!' 
        });
      });
      return;
    }

    
    dbPool.query("INSERT INTO validaciones (incidente_id, usuario_id) VALUES (?, ?)", [incidenteId, usuarioQueVota], (errVoto) => {
      if (errVoto) {
        if (errVoto.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ error: 'Ya habías registrado tu validación para este incidente.' });
        }
        return res.status(500).json({ error: 'Error al registrar la validación.' });
      }

      
      dbPool.query("SELECT COUNT(*) as total FROM validaciones WHERE incidente_id = ?", [incidenteId], (errConteo, resConteo) => {
        const totalVotos = resConteo[0].total;

        
        if (totalVotos >= 2) {
          dbPool.query("UPDATE incidentes SET estado = 'Resuelto' WHERE id = ?", [incidenteId], () => {
            return res.json({ 
              resuelto: true, 
              estado: 'Resuelto', 
              votos: totalVotos, 
              mensaje: '¡Incidente resuelto por validación comunitaria (2/2)!' 
            });
          });
        } else {
          
          return res.json({ 
            resuelto: false, 
            estado: 'Pendiente', 
            votos: totalVotos, 
            mensaje: '¡Tu voto fue registrado! Se necesita 1 confirmación más de otro vecino.' 
          });
        }
      });
    });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Servidor corriendo en el puerto ${PORT}`);
});