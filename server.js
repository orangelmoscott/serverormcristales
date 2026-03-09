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
        'http://localhost:8080',
        'http://localhost:3000'
    ],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));
app.use(bodyParser.json());



const SECRET_KEY = process.env.SECRET_KEY; // Cambia esto en tu entorno
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ Conexión a MongoDB exitosa'))
    .catch(err => console.error('❌ Error crítico al conectar a MongoDB (verifica tu URI o Acceso IP en Atlas):', err.message));



// Esquema y modelo para usuarios de administrador
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
});

const User = mongoose.model('User', userSchema);

// Esquema y modelo para contactos
const contactSchema = new mongoose.Schema({
    name: String,
    email: String,
    message: String,
});

const Contact = mongoose.model('Contact', contactSchema);

// Ruta para registrar un usuario (solo para uso inicial, después puede eliminarse)
app.post('/register', async (req, res) => {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
        username: req.body.username,
        password: hashedPassword,
    });
    await user.save();
    res.status(201).send({ message: 'Usuario registrado con éxito' });
});

// Ruta de inicio de sesión
app.post('/login', async (req, res) => {
    const user = await User.findOne({ username: req.body.username });
    if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
        return res.status(401).send({ message: 'Credenciales incorrectas' });
    }
    const token = jwt.sign({ userId: user._id }, SECRET_KEY, { expiresIn: '1h' });
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
        res.status(401).send({ message: 'Token inválido' });
    }
}

// Ruta para obtener los contactos (protegida)
app.get('/contacts', authenticate, async (req, res) => {
    const contacts = await Contact.find();
    res.send(contacts);
});

// Ruta para crear un nuevo contacto
app.post('/cliente', async (req, res) => {
    const { name, email, message } = req.body;

    try {
        const newContact = new Contact({ name, email, message });
        await newContact.save();
        res.status(201).send({ message: 'Contacto guardado con éxito' });
    } catch (error) {
        res.status(400).send({ message: 'Error al guardar el contacto', error: error.message });
    }
});


const PORT = process.env.PORT || 3000;;
app.listen(PORT, () => {
    console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
});
