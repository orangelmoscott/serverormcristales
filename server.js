// server.js — ORM Cristales API v2
// Sistema con roles (admin/cristalero), asignaciones de rutas diarias y verificación
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// ==============================
// CONFIGURACIÓN
// ==============================
const corsOptions = {
    origin: [
        'https://ormcristaleslimpios.vercel.app',
        'https://orangelmoscott.github.io',
        'https://paneladmin-phi.vercel.app',
        'https://paneladmin-orangelmoscotts-projects.vercel.app',
        'http://localhost:8080',
        'http://localhost:3000'
    ],
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));
app.use(bodyParser.json({ limit: '5mb' })); // Firma base64 puede ser grande

const SECRET_KEY = process.env.SECRET_KEY;
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ Conexión a MongoDB exitosa'))
    .catch(err => console.error('❌ Error al conectar a MongoDB:', err.message));

// ==============================
// SCHEMAS
// ==============================

// --- Usuario (admin o cristalero) ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: {
        type: String,
        enum: ['admin', 'cristalero'],
        default: 'cristalero'
    },
    fullName: { type: String, default: '' },
    phone: { type: String, default: '' },
    active: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// --- Contacto (leads del formulario público) ---
const contactSchema = new mongoose.Schema({
    name: String,
    email: String,
    telefono: String,
    message: String,
    status: {
        type: String,
        enum: ['pendiente', 'contactado', 'presupuesto_enviado'],
        default: 'pendiente'
    },
    createdAt: { type: Date, default: Date.now }
});
const Contact = mongoose.model('Contact', contactSchema);

// --- Cliente recurrente (CRM) ---
const clientSchema = new mongoose.Schema({
    companyName: { type: String, required: true },
    encargado: String,
    nif: { type: String, required: true },
    address: String,
    phone: String,
    email: { type: String, required: true },
    serviceType: {
        type: String,
        enum: ['hogar', 'oficina', 'restaurante', 'tienda'],
        required: true
    },
    frequency: {
        type: String,
        enum: ['semanal', 'quincenal', 'mensual'],
        required: true
    },
    basePrice: { type: Number, required: true },
    active: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});
const Client = mongoose.model('Client', clientSchema);

// --- Asignación de ruta diaria ---
const assignmentSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    clientId: { type: mongoose.Schema.Types.ObjectId, ref: 'Client', required: true },
    date: { type: Date, required: true },
    status: {
        type: String,
        enum: ['pendiente', 'en_ruta', 'completado'],
        default: 'pendiente'
    },
    notes: { type: String, default: '' },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdAt: { type: Date, default: Date.now }
});
// Índice compuesto para buscar rápido por cristalero + fecha
assignmentSchema.index({ userId: 1, date: 1 });
assignmentSchema.index({ date: 1 });
const Assignment = mongoose.model('Assignment', assignmentSchema);

// --- Registro de limpieza realizada ---
const serviceLogSchema = new mongoose.Schema({
    clientId: { type: mongoose.Schema.Types.ObjectId, ref: 'Client', required: true },
    performedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    assignmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Assignment' },
    date: { type: Date, default: Date.now },
    basePrice: Number,
    ivaAmount: Number,
    totalPrice: Number,
    signature: String,
    verifiedBy: String,
    status: { type: String, default: 'completado' }
});
const ServiceLog = mongoose.model('ServiceLog', serviceLogSchema);

// ==============================
// MIDDLEWARES DE AUTENTICACIÓN
// ==============================

// Autenticación general — cualquier usuario logueado
function authenticate(req, res, next) {
    const token = req.headers.authorization;
    if (!token) return res.status(401).send({ message: 'Acceso denegado' });
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).send({ message: 'Token inválido o expirado' });
    }
}

// Solo administradores
function adminOnly(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).send({ message: 'Acceso restringido a administradores' });
    }
    next();
}

// ==============================
// RUTAS DE AUTENTICACIÓN
// ==============================

// POST /register — Crear usuario (primer usuario libre, luego solo admin)
app.post('/register', async (req, res) => {
    try {
        const userCount = await User.countDocuments();

        if (userCount > 0) {
            const token = req.headers.authorization;
            if (!token) return res.status(401).send({ message: 'Se requiere autenticación para crear más usuarios.' });
            try {
                const decoded = jwt.verify(token, SECRET_KEY);
                if (decoded.role !== 'admin') {
                    return res.status(403).send({ message: 'Solo los administradores pueden crear usuarios.' });
                }
            } catch (err) {
                return res.status(401).send({ message: 'Token inválido o expirado' });
            }
        }

        const { username, password, role, fullName, phone } = req.body;

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).send({ message: 'El nombre de usuario ya está en uso' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            username,
            password: hashedPassword,
            role: userCount === 0 ? 'admin' : (role || 'cristalero'), // Primer usuario siempre admin
            fullName: fullName || '',
            phone: phone || ''
        });
        await user.save();
        res.status(201).send({ message: 'Usuario registrado con éxito', user: { _id: user._id, username: user.username, role: user.role } });
    } catch (error) {
        res.status(500).send({ message: 'Error en el registro', error: error.message });
    }
});

// POST /login — Iniciar sesión
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).send({ message: 'Credenciales incorrectas' });
        }
        const token = jwt.sign(
            { userId: user._id, username: user.username, role: user.role },
            SECRET_KEY,
            { expiresIn: '8h' }
        );
        res.send({
            token,
            username: user.username,
            role: user.role,
            fullName: user.fullName,
            userId: user._id
        });
    } catch (error) {
        res.status(500).send({ message: 'Error en el servidor' });
    }
});

// ==============================
// RUTAS DE CONTACTOS (solo admin)
// ==============================

app.get('/contacts', authenticate, adminOnly, async (req, res) => {
    try {
        const contacts = await Contact.find().sort({ createdAt: -1 });
        res.send(contacts);
    } catch (error) {
        res.status(500).send({ message: 'Error al obtener contactos' });
    }
});

// Formulario público (sin auth)
app.post('/cliente', async (req, res) => {
    const { name, email, telefono, message } = req.body;
    try {
        const newContact = new Contact({ name, email, telefono, message });
        await newContact.save();
        res.status(201).send({ message: 'Contacto guardado con éxito' });
    } catch (error) {
        res.status(400).send({ message: 'Error al guardar el contacto', error: error.message });
    }
});

app.patch('/contacts/:id/status', authenticate, adminOnly, async (req, res) => {
    const { status } = req.body;
    const validStatuses = ['pendiente', 'contactado', 'presupuesto_enviado'];
    if (!validStatuses.includes(status)) {
        return res.status(400).send({ message: 'Estado no válido' });
    }
    try {
        const contact = await Contact.findByIdAndUpdate(req.params.id, { status }, { new: true });
        if (!contact) return res.status(404).send({ message: 'Contacto no encontrado' });
        res.send({ message: 'Estado actualizado', contact });
    } catch (error) {
        res.status(500).send({ message: 'Error al actualizar el estado' });
    }
});

app.delete('/contacts/:id', authenticate, adminOnly, async (req, res) => {
    try {
        const contact = await Contact.findByIdAndDelete(req.params.id);
        if (!contact) return res.status(404).send({ message: 'Contacto no encontrado' });
        res.send({ message: 'Contacto eliminado con éxito' });
    } catch (error) {
        res.status(500).send({ message: 'Error al eliminar el contacto' });
    }
});

// ==============================
// RUTAS DE USUARIOS (solo admin)
// ==============================

app.get('/users', authenticate, adminOnly, async (req, res) => {
    try {
        const users = await User.find({}, 'username role fullName phone active _id createdAt');
        res.send(users);
    } catch (error) {
        res.status(500).send({ message: 'Error al obtener usuarios' });
    }
});

// GET solo cristaleros activos (para select de asignaciones)
app.get('/users/cristaleros', authenticate, adminOnly, async (req, res) => {
    try {
        const cristaleros = await User.find({ role: 'cristalero', active: true }, 'username fullName _id');
        res.send(cristaleros);
    } catch (error) {
        res.status(500).send({ message: 'Error al obtener cristaleros' });
    }
});

app.delete('/users/:id', authenticate, adminOnly, async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) return res.status(404).send({ message: 'Usuario no encontrado' });
        res.send({ message: 'Usuario eliminado con éxito' });
    } catch (error) {
        res.status(500).send({ message: 'Error al eliminar usuario' });
    }
});

// ==============================
// RUTAS DE CLIENTES / CRM (solo admin)
// ==============================

app.get('/clients', authenticate, adminOnly, async (req, res) => {
    try {
        const clients = await Client.find().sort({ companyName: 1 });
        res.send(clients);
    } catch (error) {
        res.status(500).send({ message: 'Error al obtener clientes' });
    }
});

app.post('/clients', authenticate, adminOnly, async (req, res) => {
    try {
        const client = new Client(req.body);
        await client.save();
        res.status(201).send({ message: 'Cliente creado con éxito', client });
    } catch (error) {
        res.status(400).send({ message: 'Error al crear cliente', error: error.message });
    }
});

app.put('/clients/:id', authenticate, adminOnly, async (req, res) => {
    try {
        const client = await Client.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!client) return res.status(404).send({ message: 'Cliente no encontrado' });
        res.send({ message: 'Cliente actualizado correctamente', client });
    } catch (error) {
        res.status(400).send({ message: 'Error al actualizar cliente', error: error.message });
    }
});

app.delete('/clients/:id', authenticate, adminOnly, async (req, res) => {
    try {
        await Client.findByIdAndDelete(req.params.id);
        res.send({ message: 'Cliente eliminado correctamente' });
    } catch (error) {
        res.status(500).send({ message: 'Error al eliminar cliente' });
    }
});

// ==============================
// RUTAS DE ASIGNACIONES (rutas diarias)
// ==============================

// GET — Todas las asignaciones de un día (admin)
app.get('/assignments', authenticate, adminOnly, async (req, res) => {
    try {
        const { date } = req.query;
        if (!date) return res.status(400).send({ message: 'Se requiere parámetro date (YYYY-MM-DD)' });

        const startOfDay = new Date(date + 'T00:00:00.000Z');
        const endOfDay = new Date(date + 'T23:59:59.999Z');

        const assignments = await Assignment.find({
            date: { $gte: startOfDay, $lte: endOfDay }
        })
            .populate('userId', 'username fullName')
            .populate('clientId', 'companyName address phone serviceType')
            .populate('createdBy', 'username')
            .sort({ userId: 1 });

        res.send(assignments);
    } catch (error) {
        res.status(500).send({ message: 'Error al obtener asignaciones', error: error.message });
    }
});

// GET — Mis asignaciones del día (cristalero)
app.get('/my-assignments', authenticate, async (req, res) => {
    try {
        const { date } = req.query;
        const targetDate = date || new Date().toISOString().split('T')[0];

        const startOfDay = new Date(targetDate + 'T00:00:00.000Z');
        const endOfDay = new Date(targetDate + 'T23:59:59.999Z');

        const assignments = await Assignment.find({
            userId: req.user.userId,
            date: { $gte: startOfDay, $lte: endOfDay }
        })
            .populate('clientId', 'companyName address phone email serviceType encargado')
            .sort({ createdAt: 1 });

        res.send(assignments);
    } catch (error) {
        res.status(500).send({ message: 'Error al obtener tus asignaciones', error: error.message });
    }
});

// POST — Crear asignación (admin)
app.post('/assignments', authenticate, adminOnly, async (req, res) => {
    try {
        const { userId, clientId, date, notes } = req.body;

        // Verificar que no exista ya esa asignación
        const startOfDay = new Date(date + 'T00:00:00.000Z');
        const endOfDay = new Date(date + 'T23:59:59.999Z');
        const exists = await Assignment.findOne({
            userId, clientId,
            date: { $gte: startOfDay, $lte: endOfDay }
        });
        if (exists) {
            return res.status(400).send({ message: 'Este cliente ya está asignado a este cristalero en esa fecha.' });
        }

        const assignment = new Assignment({
            userId,
            clientId,
            date: startOfDay,
            notes: notes || '',
            createdBy: req.user.userId
        });
        await assignment.save();

        // Devolver con populate
        const populated = await Assignment.findById(assignment._id)
            .populate('userId', 'username fullName')
            .populate('clientId', 'companyName address phone serviceType');

        res.status(201).send({ message: 'Asignación creada', assignment: populated });
    } catch (error) {
        res.status(500).send({ message: 'Error al crear asignación', error: error.message });
    }
});

// POST — Crear múltiples asignaciones de golpe (admin, para eficiencia)
app.post('/assignments/bulk', authenticate, adminOnly, async (req, res) => {
    try {
        const { userId, clientIds, date, notes } = req.body;
        const startOfDay = new Date(date + 'T00:00:00.000Z');
        const endOfDay = new Date(date + 'T23:59:59.999Z');

        const created = [];
        const skipped = [];

        for (const clientId of clientIds) {
            const exists = await Assignment.findOne({
                userId, clientId,
                date: { $gte: startOfDay, $lte: endOfDay }
            });
            if (exists) {
                skipped.push(clientId);
                continue;
            }
            const assignment = new Assignment({
                userId, clientId,
                date: startOfDay,
                notes: notes || '',
                createdBy: req.user.userId
            });
            await assignment.save();
            created.push(assignment);
        }

        res.status(201).send({
            message: `${created.length} asignaciones creadas, ${skipped.length} ya existían.`,
            created: created.length,
            skipped: skipped.length
        });
    } catch (error) {
        res.status(500).send({ message: 'Error al crear asignaciones', error: error.message });
    }
});

// PATCH — Actualizar estado de asignación
app.patch('/assignments/:id/status', authenticate, async (req, res) => {
    try {
        const { status } = req.body;
        const validStatuses = ['pendiente', 'en_ruta', 'completado'];
        if (!validStatuses.includes(status)) {
            return res.status(400).send({ message: 'Estado no válido' });
        }

        const assignment = await Assignment.findById(req.params.id);
        if (!assignment) return res.status(404).send({ message: 'Asignación no encontrada' });

        // Cristaleros solo pueden actualizar SUS asignaciones
        if (req.user.role === 'cristalero' && assignment.userId.toString() !== req.user.userId) {
            return res.status(403).send({ message: 'No tienes permiso para modificar esta asignación' });
        }

        assignment.status = status;
        await assignment.save();
        res.send({ message: 'Estado actualizado', assignment });
    } catch (error) {
        res.status(500).send({ message: 'Error al actualizar estado' });
    }
});

// DELETE — Eliminar asignación (admin)
app.delete('/assignments/:id', authenticate, adminOnly, async (req, res) => {
    try {
        const assignment = await Assignment.findByIdAndDelete(req.params.id);
        if (!assignment) return res.status(404).send({ message: 'Asignación no encontrada' });
        res.send({ message: 'Asignación eliminada' });
    } catch (error) {
        res.status(500).send({ message: 'Error al eliminar asignación' });
    }
});

// ==============================
// RUTAS DE SERVICIOS (logs de limpieza)
// ==============================

// POST — Registrar limpieza (admin o cristalero asignado)
app.post('/services/log', authenticate, async (req, res) => {
    try {
        const { clientId, signature, verifiedBy, assignmentId } = req.body;
        const client = await Client.findById(clientId);
        if (!client) return res.status(404).send({ message: 'Cliente no encontrado' });

        // Si es cristalero, verificar que la asignación es suya
        if (req.user.role === 'cristalero' && assignmentId) {
            const assignment = await Assignment.findById(assignmentId);
            if (!assignment || assignment.userId.toString() !== req.user.userId) {
                return res.status(403).send({ message: 'No tienes permiso para este registro' });
            }
            // Marcar asignación como completada
            assignment.status = 'completado';
            await assignment.save();
        }

        const basePrice = client.basePrice;
        const ivaAmount = parseFloat((basePrice * 0.21).toFixed(2));
        const totalPrice = parseFloat((basePrice + ivaAmount).toFixed(2));

        const log = new ServiceLog({
            clientId,
            performedBy: req.user.userId,
            assignmentId: assignmentId || null,
            basePrice,
            ivaAmount,
            totalPrice,
            signature,
            verifiedBy,
            date: new Date()
        });

        await log.save();
        res.status(201).send({ message: 'Servicio registrado y verificado correctamente', log });
    } catch (error) {
        res.status(500).send({ message: 'Error al registrar el servicio', error: error.message });
    }
});

// GET — Historial de un cliente (admin)
app.get('/services/logs/:clientId', authenticate, adminOnly, async (req, res) => {
    try {
        const logs = await ServiceLog.find({ clientId: req.params.clientId })
            .populate('performedBy', 'username fullName')
            .sort({ date: -1 });
        res.send(logs);
    } catch (error) {
        res.status(500).send({ message: 'Error al obtener el historial' });
    }
});

// GET — Resumen del día para el dashboard admin
app.get('/dashboard/today', authenticate, adminOnly, async (req, res) => {
    try {
        const today = new Date().toISOString().split('T')[0];
        const startOfDay = new Date(today + 'T00:00:00.000Z');
        const endOfDay = new Date(today + 'T23:59:59.999Z');

        const totalAssignments = await Assignment.countDocuments({
            date: { $gte: startOfDay, $lte: endOfDay }
        });
        const completedAssignments = await Assignment.countDocuments({
            date: { $gte: startOfDay, $lte: endOfDay },
            status: 'completado'
        });
        const totalCristaleros = await User.countDocuments({ role: 'cristalero', active: true });
        const pendingContacts = await Contact.countDocuments({ status: 'pendiente' });

        res.send({
            totalAssignments,
            completedAssignments,
            totalCristaleros,
            pendingContacts,
            completionRate: totalAssignments > 0 ? Math.round((completedAssignments / totalAssignments) * 100) : 0
        });
    } catch (error) {
        res.status(500).send({ message: 'Error al obtener resumen' });
    }
});

// ==============================
// SERVIDOR
// ==============================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 ORM Cristales API v2 ejecutándose en http://localhost:${PORT}`);
});
