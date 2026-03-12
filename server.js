// server.js
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// CORS Configuration
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
app.use(bodyParser.json());

const SECRET_KEY = process.env.SECRET_KEY;
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ Conexión a MongoDB exitosa'))
    .catch(err => console.error('❌ Error al conectar a MongoDB:', err.message));

// ---- SCHEMAS ----

// Esquema y modelo para usuarios de administrador
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
});
const User = mongoose.model('User', userSchema);

// Esquema y modelo para contactos (actualizado con teléfono y estado)
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

// ---- SCHEMAS PROFESIONALES (CLIENTES Y SERVICIOS) ----

// Esquema para Clientes Recurrentes (Empresas/Particulares)
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
    basePrice: { type: Number, required: true }, // Precio sin IVA
    active: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const Client = mongoose.model('Client', clientSchema);

// Esquema para Registro de Limpiezas Realizadas (Logs)
const serviceLogSchema = new mongoose.Schema({
    clientId: { type: mongoose.Schema.Types.ObjectId, ref: 'Client', required: true },
    date: { type: Date, default: Date.now },
    basePrice: Number,
    ivaAmount: Number,
    totalPrice: Number,
    signature: String, // Base64 de la firma táctil
    verifiedBy: String, // Nombre de quien firma
    status: { type: String, default: 'completado' }
});

const ServiceLog = mongoose.model('ServiceLog', serviceLogSchema);

// ---- RUTAS AUTH ----

// Ruta para registrar un usuario (Protegida si ya existen usuarios)
app.post('/register', async (req, res) => {
    try {
        const userCount = await User.countDocuments();

        // Si ya hay usuarios, verificar autenticación
        if (userCount > 0) {
            const token = req.headers.authorization;
            if (!token) return res.status(401).send({ message: 'Se requiere autenticación para crear más usuarios.' });

            try {
                jwt.verify(token, SECRET_KEY);
            } catch (err) {
                return res.status(401).send({ message: 'Token inválido o expirado' });
            }
        }

        const { username, password } = req.body;

        // Verificar si el usuario ya existe
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).send({ message: 'El nombre de usuario ya está en uso' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword });
        await user.save();
        res.status(201).send({ message: 'Usuario registrado con éxito' });
    } catch (error) {
        res.status(500).send({ message: 'Error en el registro', error: error.message });
    }
});

// Ruta de inicio de sesión
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).send({ message: 'Credenciales incorrectas' });
        }
        const token = jwt.sign({ userId: user._id, username: user.username }, SECRET_KEY, { expiresIn: '8h' });
        res.send({ token, username: user.username });
    } catch (error) {
        res.status(500).send({ message: 'Error en el servidor' });
    }
});

// Middleware de autenticación
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

// ---- RUTAS CONTACTOS ----

// GET - Obtener todos los contactos (protegida)
app.get('/contacts', authenticate, async (req, res) => {
    try {
        const contacts = await Contact.find().sort({ createdAt: -1 });
        res.send(contacts);
    } catch (error) {
        res.status(500).send({ message: 'Error al obtener contactos' });
    }
});

// POST - Crear un nuevo contacto (desde la web pública)
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

// PATCH - Actualizar estado de un contacto (protegida)
app.patch('/contacts/:id/status', authenticate, async (req, res) => {
    const { status } = req.body;
    const validStatuses = ['pendiente', 'contactado', 'presupuesto_enviado'];
    if (!validStatuses.includes(status)) {
        return res.status(400).send({ message: 'Estado no válido' });
    }
    try {
        const contact = await Contact.findByIdAndUpdate(
            req.params.id,
            { status },
            { new: true }
        );
        if (!contact) return res.status(404).send({ message: 'Contacto no encontrado' });
        res.send({ message: 'Estado actualizado', contact });
    } catch (error) {
        res.status(500).send({ message: 'Error al actualizar el estado' });
    }
});

// DELETE - Eliminar un contacto (protegida)
app.delete('/contacts/:id', authenticate, async (req, res) => {
    try {
        const contact = await Contact.findByIdAndDelete(req.params.id);
        if (!contact) return res.status(404).send({ message: 'Contacto no encontrado' });
        res.send({ message: 'Contacto eliminado con éxito' });
    } catch (error) {
        res.status(500).send({ message: 'Error al eliminar el contacto' });
    }
});

// ---- RUTAS USUARIOS (GESTIÓN EQUIPO) ----

// GET - Listar usuarios (protegida)
app.get('/users', authenticate, async (req, res) => {
    try {
        const users = await User.find({}, 'username _id');
        res.send(users);
    } catch (error) {
        res.status(500).send({ message: 'Error al obtener usuarios' });
    }
});

// DELETE - Eliminar usuario (protegida)
app.delete('/users/:id', authenticate, async (req, res) => {
    try {
        // Evitar que un usuario se elimine a sí mismo (opcional)
        // const decoded = jwt.verify(req.headers.authorization, SECRET_KEY);
        // if (decoded.userId === req.params.id) {
        //     return res.status(400).send({ message: 'No puedes eliminar tu propia cuenta' });
        // }

        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) return res.status(404).send({ message: 'Usuario no encontrado' });
        res.send({ message: 'Usuario eliminado con éxito' });
    } catch (error) {
        res.status(500).send({ message: 'Error al eliminar usuario' });
    }
});

// ---- RUTAS CLIENTES (CRM) ----

// GET - Listar todos los clientes
app.get('/clients', authenticate, async (req, res) => {
    try {
        const clients = await Client.find().sort({ companyName: 1 });
        res.send(clients);
    } catch (error) {
        res.status(500).send({ message: 'Error al obtener clientes' });
    }
});

// POST - Crear nuevo cliente
app.post('/clients', authenticate, async (req, res) => {
    try {
        const client = new Client(req.body);
        await client.save();
        res.status(201).send({ message: 'Cliente creado con éxito', client });
    } catch (error) {
        res.status(400).send({ message: 'Error al crear cliente', error: error.message });
    }
});

// DELETE - Eliminar cliente
app.delete('/clients/:id', authenticate, async (req, res) => {
    try {
        await Client.findByIdAndDelete(req.params.id);
        res.send({ message: 'Cliente eliminado correctamente' });
    } catch (error) {
        res.status(500).send({ message: 'Error al eliminar cliente' });
    }
});

// ---- RUTAS SERVICIOS (LOGS Y FIRMAS) ----

// POST - Registrar una limpieza realizada
app.post('/services/log', authenticate, async (req, res) => {
    try {
        const { clientId, signature, verifiedBy } = req.body;
        const client = await Client.findById(clientId);
        if (!client) return res.status(404).send({ message: 'Cliente no encontrado' });

        const basePrice = client.basePrice;
        const ivaAmount = parseFloat((basePrice * 0.21).toFixed(2));
        const totalPrice = parseFloat((basePrice + ivaAmount).toFixed(2));

        const log = new ServiceLog({
            clientId,
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

// GET - Obtener historial de servicios de un cliente
app.get('/services/logs/:clientId', authenticate, async (req, res) => {
    try {
        const logs = await ServiceLog.find({ clientId: req.params.clientId }).sort({ date: -1 });
        res.send(logs);
    } catch (error) {
        res.status(500).send({ message: 'Error al obtener el historial' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
});
