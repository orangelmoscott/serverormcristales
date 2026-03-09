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

// ---- RUTAS AUTH ----

// Ruta para registrar un usuario (solo para uso inicial)
app.post('/register', async (req, res) => {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({ username: req.body.username, password: hashedPassword });
    await user.save();
    res.status(201).send({ message: 'Usuario registrado con éxito' });
});

// Ruta de inicio de sesión
app.post('/login', async (req, res) => {
    const user = await User.findOne({ username: req.body.username });
    if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
        return res.status(401).send({ message: 'Credenciales incorrectas' });
    }
    const token = jwt.sign({ userId: user._id }, SECRET_KEY, { expiresIn: '8h' });
    res.send({ token });
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
});
