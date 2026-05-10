// server.js — ORM Cristales API v2
// Sistema con roles (admin/cristalero), asignaciones de rutas diarias y verificación
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const dns = require('dns');
const PDFDocument = require('pdfkit');

// Forzar preferencia de IPv4 para evitar errores de conexión (ENETUNREACH) en entornos sin IPv6 (como Render)

if (dns.setDefaultResultOrder) {
    dns.setDefaultResultOrder('ipv4first');
}


const app = express();

// ==============================
// CONFIGURACIÓN
// ==============================
const corsOptions = {
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));
app.use(bodyParser.json({ limit: '5mb' })); // Firma base64 puede ser grande

const SECRET_KEY = process.env.SECRET_KEY;
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ Conexión a MongoDB exitosa'))
    .catch(err => console.error('❌ Error al conectar a MongoDB:', err.message));

// --- Configuración de Correo (SMTP) ---
const EMAIL_USER = (process.env.EMAIL_USER || "").trim().replace(/['"]/g, "");
const EMAIL_PASS = (process.env.EMAIL_PASS || "").trim().replace(/['"]/g, "");

// Transporter reutilizable para mayor eficiencia
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false, // TLS/STARTTLS para el puerto 587
    auth: {
        user: EMAIL_USER,
        pass: EMAIL_PASS
    },
    tls: {
        rejectUnauthorized: false
    },
    connectionTimeout: 10000,
    family: 4 // Forzar IPv4 para evitar errores ENETUNREACH en hosts sin soporte IPv6 (como Render)
});



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

// --- Contador para Números de Factura ---
const counterSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    seq: { type: Number, default: 0 }
});
const Counter = mongoose.model('Counter', counterSchema);


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

app.get('/fix-roles', async (req, res) => {
    try {
        await User.updateMany({}, { role: 'admin' });
        res.send('Todos los usuarios convertidos a admin.');
    } catch (e) {
        res.send(e.message);
    }
});

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
        console.error('❌ Error detallado en /login:', error);
        res.status(500).send({ message: 'Error en el servidor', error: error.message });
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

app.post('/clients/:id/invoice-email', authenticate, adminOnly, async (req, res) => {
    try {
        const client = await Client.findById(req.params.id);
        if (!client) return res.status(404).send({ message: 'Cliente no encontrado' });
        if (!client.email) return res.status(400).send({ message: 'El cliente no tiene un email registrado' });

        const base = client.basePrice;
        const iva = base * 0.21;
        const total = base + iva;
        const dateStr = new Date().toLocaleDateString('es-ES', { month: 'long', year: 'numeric' });
        const capitalize = s => s && s.charAt(0).toUpperCase() + s.slice(1);

        // --- Obtener/Incrementar Número de Factura ---
        let counter = await Counter.findOneAndUpdate(
            { id: 'invoice' },
            { $inc: { seq: 1 } },
            { new: true, upsert: true }
        );
        const invoiceNum = counter.seq.toString().padStart(3, '0');

        const htmlContent = `

        <div style="font-family: 'Helvetica Neue', Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.05);">
            <div style="background: linear-gradient(135deg, #0ea5e9, #0284c7); padding: 40px 30px; text-align: center;">
                <h1 style="color: white; margin: 0; font-size: 28px; letter-spacing: -0.5px;">ORM Cristales</h1>
                <p style="color: #e0f2fe; margin-top: 8px; font-size: 15px; font-weight: 500;">Limpiezas Industriales y Mantenimiento</p>
            </div>
            <div style="padding: 40px 30px;">
                <h2 style="color: #0f172a; margin-top: 0; font-size: 22px;">¡Hola ${client.companyName}!</h2>
                <p style="color: #475569; line-height: 1.6; font-size: 15px;">Queremos agradecerte por confiar un mes más en nuestros servicios de limpieza. <strong>Adjuntamos tu factura oficial en formato PDF</strong> correspondiente a los servicios realizados este mes de <strong>${capitalize(dateStr)}</strong>.</p>
                
                <div style="background: #f8fafc; padding: 25px; border-radius: 12px; margin: 30px 0; border: 1px solid #f1f5f9;">
                    <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #e0f2fe; padding-bottom: 12px; margin-bottom: 15px;">
                        <h3 style="margin: 0; color: #0369a1; font-size: 16px; text-transform: uppercase; letter-spacing: 0.5px;">Resumen Mensual</h3>
                        <span style="background: #e0f2fe; color: #0369a1; padding: 4px 12px; border-radius: 99px; font-size: 12px; font-weight: 700;">FACTURA #${invoiceNum}</span>
                    </div>
                    <table style="width: 100%; border-collapse: collapse; font-size: 15px;">

                        <tr>
                            <td style="padding: 10px 0; color: #64748b;">Concepto:</td>
                            <td style="padding: 10px 0; text-align: right; font-weight: 600; color: #0f172a;">Limpieza de ${client.serviceType}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px 0; color: #64748b;">Frecuencia:</td>
                            <td style="padding: 10px 0; text-align: right; font-weight: 600; color: #0f172a; text-transform: capitalize;">${client.frequency}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px 0; color: #64748b; border-top: 1px solid #e2e8f0; padding-top: 15px; margin-top: 5px;">Base Imponible:</td>
                            <td style="padding: 10px 0; text-align: right; font-weight: 600; color: #0f172a; border-top: 1px solid #e2e8f0; padding-top: 15px;">${base.toFixed(2)}€</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px 0; color: #64748b;">IVA Aplicado (21%):</td>
                            <td style="padding: 10px 0; text-align: right; font-weight: 600; color: #0f172a;">${iva.toFixed(2)}€</td>
                        </tr>
                        <tr>
                            <td style="padding: 20px 0 5px; color: #0ea5e9; font-weight: 800; font-size: 18px;">TOTAL A PAGAR:</td>
                            <td style="padding: 20px 0 5px; text-align: right; font-weight: 800; font-size: 20px; color: #0ea5e9;">${total.toFixed(2)}€</td>
                        </tr>
                    </table>
                </div>

                <p style="color: #475569; line-height: 1.6; font-size: 15px;">Adjuntamos la factura oficial en PDF para tu comodidad. Si tienes cualquier duda sobre la facturación, no dudes en contactarnos respondiendo a este correo.</p>

                
                <div style="text-align: center; margin-top: 35px;">
                    <a href="https://orangelmoscott.github.io/ormcristaleslimpios" style="background: #0ea5e9; color: white; text-decoration: none; padding: 14px 30px; border-radius: 999px; font-weight: 700; font-size: 15px; display: inline-block; box-shadow: 0 4px 10px rgba(14, 165, 233, 0.3);">Visitar nuestra Web</a>
                </div>
            </div>
            
            <div style="background: #f1f5f9; padding: 30px; text-align: center; border-top: 1px solid #e2e8f0;">
                <h4 style="color: #0f172a; margin-top: 0; font-size: 16px;">¿Qué te ha parecido nuestro servicio? ⭐⭐⭐⭐⭐</h4>
                <p style="color: #64748b; font-size: 14px; line-height: 1.6; max-width: 400px; margin: 10px auto 20px;">Nos ayuda enormemente que valores el esfuerzo y dedicación que ponemos en tu negocio dejando una pequeña reseña en Google.</p>
                <a href="https://g.page/r/CYg2hQ_ECr6fEBM/review" style="color: #0284c7; text-decoration: none; font-weight: 700; font-size: 15px; background: white; padding: 10px 20px; border-radius: 8px; border: 1px solid #cbd5e1; display: inline-block;">Dejar una reseña en Google</a>
            </div>
        </div>
        `;

        // --- DIAGNÓSTICO ---
        console.log(`--- Intento de envío ---`);
        console.log(`Email User: ${EMAIL_USER || "NO DEFINIDO"}`);
        console.log(`Email Pass longitud: ${EMAIL_PASS.length}`);

        if (!EMAIL_USER || !EMAIL_PASS) {
            console.log("⚠️ Faltan credenciales SMTP. Abortando.");
            return res.status(200).send({ message: 'Envío simulado (Falta configuración SMTP en Servidor).' });
        }

        try {
            console.log("Generando PDF de la factura...");
            
            // --- GENERACIÓN DEL PDF (In-Memory Buffer) ---
            const doc = new PDFDocument({ margin: 50, size: 'A4' });
            let buffers = [];
            doc.on('data', buffers.push.bind(buffers));
            
            const pdfPromise = new Promise((resolve) => {
                doc.on('end', () => {
                    resolve(Buffer.concat(buffers));
                });
            });

            // HEADER / LOGO (Placeholder o Texto)
            doc.fillColor("#0284c7").fontSize(20).text("ORM CRISTALES", { align: 'right' });
            doc.fillColor("#475569").fontSize(10).text("Limpiezas Industriales y Mantenimiento", { align: 'right' });
            doc.fillColor("#64748b").fontSize(12).text(`Factura Nº: ${invoiceNum}`, { align: 'right' });
            doc.moveDown();


            // INFO VENDEDOR / CLIENTE
            doc.fillColor("#0f172a").fontSize(12).text("DATOS DE LA EMPRESA:", { underline: true });
            doc.fontSize(10).text("ORM Cristales S.L.");
            doc.text("Calle Limpieza 123, 28001 Madrid");
            doc.text("NIF: B00000000");
            doc.moveDown();

            doc.fontSize(12).text("DATOS DEL CLIENTE:", { underline: true });
            doc.fontSize(10).text(`Cliente: ${client.companyName}`);
            doc.text(`NIF/CIF: ${client.nif || 'No especificado'}`);
            doc.text(`Dirección: ${client.address || 'No especificada'}`);
            doc.moveDown();

            // TABLA DE SERVICIOS (Simulada con líneas)
            doc.rect(50, doc.y, 500, 20).fill("#f1f5f9");
            doc.fillColor("#0f172a").fontSize(10).text("Concepto", 60, doc.y - 15);
            doc.text("Frecuencia", 300, doc.y - 15);
            doc.text("Total", 480, doc.y - 15);
            doc.moveDown(0.5);

            doc.text(`Limpieza de ${client.serviceType}`, 60, doc.y);
            doc.text(`${client.frequency}`, 300, doc.y);
            doc.text(`${base.toFixed(2)}€`, 480, doc.y);
            doc.moveDown();

            // TOTALES
            doc.moveTo(350, doc.y).lineTo(550, doc.y).stroke("#e2e8f0");
            doc.moveDown(0.5);
            doc.text("Base Imponible:", 350, doc.y);
            doc.text(`${base.toFixed(2)}€`, 480, doc.y);
            doc.moveDown();
            doc.text("IVA (21%):", 350, doc.y);
            doc.text(`${iva.toFixed(2)}€`, 480, doc.y);
            doc.moveDown();
            doc.fillColor("#0ea5e9").fontSize(14).text("TOTAL FACTURA:", 350, doc.y);
            doc.text(`${total.toFixed(2)}€`, 480, doc.y);

            doc.moveDown(2);
            doc.fillColor("#64748b").fontSize(9).text("Gracias por su confianza. Esta es una factura generada automáticamente.", { align: 'center', italic: true });

            doc.end();
            const pdfBuffer = await pdfPromise;

            // --- ENVÍO DEL EMAIL CON ADJUNTO ---
            console.log("Enviando email con adjunto...");
            await transporter.sendMail({
                from: `"ORM Cristales" <${EMAIL_USER}>`,
                to: client.email,
                subject: `Factura #${invoiceNum} - ${capitalize(dateStr)} - ORM Cristales`,
                html: htmlContent,
                attachments: [
                    {
                        filename: `Factura_ORM_${invoiceNum}_${client.companyName.replace(/\s+/g, '_')}.pdf`,
                        content: pdfBuffer
                    }
                ]
            });


            console.log("✅ Email y Factura PDF enviados correctamente.");
            res.status(200).send({ message: 'Correo con factura PDF enviado con éxito' });
        } catch (mailError) {
            console.error("❌ Error en el proceso de correo/pdf:", mailError);
            res.status(500).send({ message: 'Error en el servidor de correo o generación de PDF', error: mailError.message });
        }
    } catch (error) {
        console.error("❌ Error General en /invoice-email:", error);
        res.status(500).send({ message: 'Error al procesar la solicitud', error: error.message });
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
