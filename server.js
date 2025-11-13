require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const moment = require('moment');
const nodemailer = require("nodemailer");
const http = require('http');
const mqtt = require('mqtt');
const { Server } = require('socket.io');

var admin = require("firebase-admin");

var serviceAccount = require("./ztrackk-bfbc3-firebase-adminsdk-fbsvc-10fb4d407b.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});




// Import Models
const Location = require('./models/LocationsModel');


const verifiedEmails = new Set();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*", // Allow all origins (modify in production)
  }
});
app.use(bodyParser.json());
app.use(cors());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// Models
const UserSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  dateOfBirth: String,
  verificationCode: String,
  isVerified: { type: Boolean, default: false },
  isVerifiedForReset: { type: Boolean, default: false },
});
const User = mongoose.model('User', UserSchema, 'users');

const PatientSchema = new mongoose.Schema({
  fullName: String,
  dateOfBirth: String,
  diseases: String,
  safeZone: Number,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
});
const Patient = mongoose.model('Patient', PatientSchema, 'patients');

// Define a schema for alerts
const alertSchema = new mongoose.Schema({
  patientId: { type: String, default: 'patient_1' },
  timestamp: { type: Date, default: Date.now },
  message: String,
},
{ timestamps: true });
const Alert = mongoose.model('Alert',alertSchema, 'alerts');

// Nodemailer config
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USERNAME,
    pass: process.env.EMAIL_PASSWORD,
  },
});
//signup-init
const pendingUsers = new Map(); // { email: { hashedPassword, verificationCode, expiryTime } }

app.post("/signup-init", async (req, res) => {
  const { email, password } = req.body;

  try {
    console.log(`/signup-init called with email: ${email}`);

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.log('Email already exists');
      return res.status(400).json({ message: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiryTime = Date.now() + 120000; // 2 min

    // temporel saving
    pendingUsers.set(email, { hashedPassword, verificationCode, expiryTime });

    // send code by email
    await transporter.sendMail({
      from: process.env.EMAIL_USERNAME,
      to: email,
      subject: "Verification Code",
      text: `Your verification code is: ${verificationCode}`,
    });

    res.json({ message: "Verification code sent to email" });
  } catch (error) {
    console.error("Error in /signup-init:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

//confirm code
app.post("/confirm-code", (req, res) => {
  const { email, code } = req.body;
  const pendingUser = pendingUsers.get(email);

  if (!pendingUser) {
    return res.status(400).json({ message: "No pending signup found for this email" });
  }

  if (pendingUser.verificationCode === code) {
    verifiedEmails.add(email); 

    res.json({ message: "Email verified, now complete your profile" });
  } else {
    res.status(400).json({ message: "Invalid verification code" });
  }
});


//signup-complete
app.post("/signup-complete", async (req, res) => {
  const { email, username, dateOfBirth } = req.body;

  if (!verifiedEmails.has(email)) {
    return res.status(400).json({ message: "Email not verified" });
  }

  const pendingUser = pendingUsers.get(email);
  if (!pendingUser) {
    return res.status(400).json({ message: "Pending user data not found" });
  }

  const hashedPassword = pendingUser.hashedPassword;

  try {
    const newUser = new User({
      email: email,
      password: hashedPassword,
      username: username,
      dateOfBirth: dateOfBirth,
      isVerified: true,
    });

    await newUser.save();

    //Create the token after saving the user
    const token = jwt.sign({ _id: newUser._id }, process.env.JWT_SECRET);

    // cleaning
    verifiedEmails.delete(email);
    pendingUsers.delete(email);

    res.json({ message: "Signup complete", token });
  } catch (error) {
    console.error("Error completing signup:", error);
    res.status(500).json({ message: "Error completing signup" });
  }
});


// Resend verification code
app.post('/resend-verification-code', async (req, res) => {
  const { email } = req.body;

  try {
    console.log(`/resend-verification-code called with email: ${email}`);
    const pendingUser = pendingUsers.get(email);
    if (!pendingUser) {
      console.log('No pending signup found');
      return res.status(404).json({ message: "No pending signup found" });
    }

    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiryTime = Date.now() + 120000; // 2 minutes (120000 ms)

    pendingUser.verificationCode = verificationCode;
    pendingUser.expiryTime = expiryTime;

    const mailOptions = {
      from: process.env.EMAIL_USERNAME,
      to: email,
      subject: "Resend Verification Code",
      text: `Your new verification code is: ${verificationCode}`,
    };

    transporter.sendMail(mailOptions, (err) => {
      if (err) {
        console.error("Error sending email:", err);
        return res.status(500).json({ message: "Failed to send verification email", error: err.message });
      }
      console.log('New verification code sent successfully');
      res.status(200).json({ message: "Verification code resent to email" });
    });
  } catch (error) {
    console.error("Error in /resend-verification-code:", error);
    res.status(500).json({ message: "Internal server error", error: error.message });
  }
});


// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    console.log(`/login called with email: ${email}`); 
    const user = await User.findOne({ email });
    if (!user) {
      console.log("User not found");
      return res.status(400).json({ message: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log("Invalid password");
      return res.status(400).json({ message: 'Invalid password' });
    }

    if (!user.isVerified) {
      console.log("Please verify your email first");
      return res.status(403).json({ message: 'Please verify your email first' });
    }
    console.log("Login successful");
    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
    res.json({ token });
  } catch (error) {
    console.error("Error in /login:", error);
    res.status(500).json({ message: "Internal server error", error: error.message }); // Include the error
  }
});

// JWT middleware
const verifyToken = (req, res, next) => {
  const authHeader = req.header('Authorization');
  if (!authHeader) {
    console.log("Access denied - no token");
    return res.status(401).json({ message: 'Access denied' });
  }

  const token = authHeader.split(' ')[1]; 
  if (!token) {
    console.log("Access denied - token not found");
    return res.status(401).json({ message: 'Access denied' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error("Error in verifyToken:", error);
    res.status(400).json({ message: 'Invalid token' });
  }
};


// Changer mot de passe
app.put('/change-password', verifyToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  if (!oldPassword || !newPassword) {
    return res.status(400).json({ message: "Please enter all information." });
  }

  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ message: "user is not found" });
    }

    // verify the old password
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "the password is incorrect" });
    }

    // set a new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    await user.save();

    res.json({ message:"Password changed successfully" });
  } catch (error) {
    console.error("Error in /change-password:", error);
    res.status(500).json({ message: "error in sever", error: error.message });
  }
});


// Add new patient
app.post('/patients', verifyToken, async (req, res) => {
  const { fullName, dateOfBirth, diseases, safeZone } = req.body;
  console.log("/patients called (POST)");

  try {
    const formattedDateOfBirth = moment(dateOfBirth, 'DD/MM/YYYY').format('YYYY-MM-DD');
    if (!moment(formattedDateOfBirth, 'YYYY-MM-DD', true).isValid()) {
      console.log("Invalid date format");
      return res.status(400).json({ message: "Invalid date format. Please use DD/MM/YYYY." });
    }
    const newPatient = new Patient({
      fullName,
      dateOfBirth: formattedDateOfBirth,
      diseases,
      safeZone,
      userId: req.user._id,
    });

    await newPatient.save();
    console.log("Patient added");
    res.status(201).json(newPatient);
  } catch (error) {
    console.error("Error in /patients (POST):", error);
    res.status(400).json({ message: 'Error adding patient', error: error.message }); 
  }
});

// Get all patients
app.get('/patients', verifyToken, async (req, res) => {
  console.log("/patients called (GET)");
  try {
    const patients = await Patient.find({ userId: req.user._id });
    console.log("Patients retrieved");
    res.json(patients);
  } catch (error) {
    console.error("Error in /patients (GET):", error);
    res.status(400).json({ message: 'Error retrieving patients', error: error.message }); 
  }
});

// Get one patient
app.get('/patients/:id', verifyToken, async (req, res) => {
  console.log(`/patients/:id called (GET) with id: ${req.params.id}`);
  try {
    const patient = await Patient.findById(req.params.id);
    if (!patient) {
      console.log("Patient not found");
      return res.status(404).json({ message: 'Patient not found' });
    }
    console.log("Patient found");
    res.json(patient);
  } catch (error) {
    console.error("Error in /patients/:id (GET):", error);
    res.status(400).json({ message: 'Error retrieving patient', error: error.message }); 
  }
});

// Update patient
app.put('/patients/:id', verifyToken, async (req, res) => {
  console.log(`/patients/:id called (PUT) with id: ${req.params.id}`);
  try {
    const patient = await Patient.findById(req.params.id);
    if (!patient) {
      console.log("Patient not found");
      return res.status(404).json({ message: 'Patient not found' });
    }

    if (patient.userId.toString() !== req.user._id.toString()) {
      console.log("Access denied");
      return res.status(403).json({ message: 'Access denied' });
    }

    Object.assign(patient, req.body);
    await patient.save();
    console.log("Patient updated successfully!");
    res.status(200).json({
     success: true,
     message: "Patient updated successfully",
      data: patient
    });
  } catch (error) {
    console.error("Error in /patients/:id (PUT):", error);
    res.status(400).json({ message: 'Error updating patient', error: error.message }); 
  }
});

// Delete patient
app.delete('/patients/:id', verifyToken, async (req, res) => {
  console.log(`/patients/:id called (DELETE) with id: ${req.params.id}`);
  try {
    const patient = await Patient.findById(req.params.id);
    if (!patient) {
      console.log("Patient not found");
      return res.status(404).json({ message: 'Patient not found' });
    }

    if (patient.userId.toString() !== req.user._id.toString()) {
      console.log("Access denied");
      return res.status(403).json({ message: 'Access denied' });
    }

    await patient.deleteOne(); 
    console.log("Patient deleted");
    res.status(200).json({ message: 'Patient deleted' });
  } catch (error) {
    console.error("Error in /patients/:id (DELETE):", error);
    res.status(400).json({ message: 'Error deleting patient', error: error.message });
  }
});


// Update user info
app.put('/user', verifyToken, async (req, res) => {
  console.log("/user called (PUT)");
  try {
    const { username, dateOfBirth } = req.body;

    const user = await User.findById(req.user._id);
    if (!user) {
      console.log("User not found");
      return res.status(404).json({ message: 'User not found' });
    }

    if (username) user.username = username;
    if (dateOfBirth) user.dateOfBirth = dateOfBirth;

    await user.save();
    console.log("User updated");
    res.json({ message: 'User updated', user });
  } catch (error) {
    console.error("Error in /user (PUT):", error);
    res.status(400).json({ message: 'Error updating user', error: error.message });
  }
});

// Get current user info (profile)
app.get('/user', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password -verificationCode -codeExpiry');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(400).json({ message: 'Error fetching user', error: error.message });
  }
});


// Delete user account
app.delete('/user', verifyToken, async (req, res) => {
  console.log("/user called (DELETE)");
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      console.log("User not found");
      return res.status(404).json({ message: 'User not found' });
    }

    // Delete all patients linked to this user
    await Patient.deleteMany({ userId: user._id });

    await user.deleteOne();
    console.log("User and associated patients deleted");
    res.json({ message: 'User and all associated data deleted' });
  } catch (error) {
    console.error("Error in /user (DELETE):", error);
    res.status(400).json({ message: 'Error deleting user', error: error.message });
  }
});

// POST /forgot-password-init
app.post('/forgot-password-init', async (req, res) => {
  const { email } = req.body;
  console.log(`/forgot-password-init called with email: ${email}`);

  try {
    const user = await User.findOne({ email });
    if (!user) {
      console.log("User not found");
      return res.status(404).json({ message: "User not found" });
    }

    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = Date.now() + 5 * 60 * 1000; //  5 min

    // Store the code and its expiration date in the user
    user.verificationCode = resetCode;
    user.codeExpiry = expiry;
    await user.save();

    await transporter.sendMail({
      from: process.env.EMAIL_USERNAME,
      to: email,
      subject: "Password Reset Code",
      text: `Your password reset code is: ${resetCode}`,
    });

    console.log("Reset code email sent");
    res.json({ message: "Reset code sent to your email" });
  } catch (error) {
    console.error("Error in /forgot-password-init:", error);
    res.status(500).json({ message: "Internal server error", error: error.message });
  }
});

// POST /forgot-password-verify
app.post('/forgot-password-verify', async (req, res) => {
  const { email, code } = req.body;
  console.log(`/forgot-password-verify called with email: ${email}, code: ${code}`);

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.verificationCode !== code) {
      return res.status(400).json({ message: "Invalid verification code" });
    }

    if (Date.now() > user.codeExpiry) {
      return res.status(400).json({ message: "Verification code expired" });
    }

    // If the code is correct and still valid
    user.verificationCode = null;
    user.codeExpiry = null;
    user.isVerifiedForReset = true; 
    await user.save();

    res.json({ message: "Code verified. You may now reset your password." });
  } catch (error) {
    console.error("Error in /forgot-password-verify:", error);
    res.status(500).json({ message: "Internal server error", error: error.message });
  }
});

// POST /forgot-password-complete
app.post('/forgot-password-complete', async (req, res) => {
  const { email, newPassword } = req.body;
  console.log(`/forgot-password-complete called with email: ${email}`);

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (!user.isVerifiedForReset) {
      return res.status(400).json({ message: "Email not verified for password reset" });
    }
    if (!email || !newPassword) {
      return res.status(400).json({ message: 'Email or new password is missing' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    // cleaning temporel data
    user.isVerifiedForReset = false;
    await user.save();

    res.json({ message: "Password has been reset successfully" });
  } catch (error) {
    console.error("Error in /forgot-password-complete:", error);
    res.status(500).json({ message: "Internal server error", error: error.message });
  }
});

// MQTT Connection
const client = mqtt.connect(`mqtts://${process.env.MQTT_USER}:${process.env.MQTT_PASSWORD}@${process.env.MQTT_ENDPOINT}`);
client.on('connect', () => {
  console.log("Connected to MQTT Broker");
  client.subscribe('patient/location');
});

// Safe Zone Configuration
const safeZone = {
  center: { 
    lat: parseFloat(process.env.SAFE_ZONE_LAT),
    lon: parseFloat(process.env.SAFE_ZONE_LON)
  },
  radius: 140 // meters
};

// Haversine Formula
function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371e3; // Earth radius in meters
  const φ1 = lat1 * Math.PI / 180;
  const φ2 = lat2 * Math.PI / 180;
  const Δφ = (lat2 - lat1) * Math.PI / 180;
  const Δλ = (lon2 - lon1) * Math.PI / 180;

  const a = Math.sin(Δφ/2) ** 2 + Math.cos(φ1) * Math.cos(φ2) * Math.sin(Δλ/2) ** 2;
  return 2 * R * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

// MQTT Message Handling
client.on('message', async (topic, message) => {
  try {
    const location = JSON.parse(message.toString());
    const newLocation = new Location({ lat: location.lat, lon: location.lon });
    console.log('Document to save:', newLocation); 
    await newLocation.save();

    // Broadcast real-time location
   io.emit('realTimeLocation', location);

    // Check safe zone
    const distance = calculateDistance(
      location.lat,
      location.lon,
      safeZone.center.lat,
      safeZone.center.lon
    );

    if (distance > safeZone.radius) {
      const alertMessage = "Your Patient Has Exceeded The Safe Zone";
      const newAlert = new Alert({ message: alertMessage });
      await newAlert.save();
      io.emit('alert', alertMessage);
      const message = {
    notification: {
      title: 'Alert',
      body: alertMessage,
    },
    topic: 'safezone',  
  };

  admin.messaging().send(message)
    .then((response) => {
      console.log('Successfully sent message:', response);
    })
    .catch((error) => {
      console.error('Error sending message:', error);
    });
       
    }

  } catch (err) {
    console.error('Error processing message:', err);
    io.emit('error', err);
  }
});

app.get('/notifications', async (req, res) => {
  try {
    const notifications = await Alert.find().sort({ createdAt: -1 }); 
    res.json(notifications);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});
//delete notification
app.delete('/notifications/:notificationId', async (req, res) => {
  const notificationId = req.params.notificationId;

  try {
    const deletedNotification = await Alert.findByIdAndDelete(notificationId);

    if (!deletedNotification) {
      return res.status(404).json({ message: 'notification not found' });
    }

    res.status(204).send(); 
    console.log(` notifiction deleted with succes: ${notificationId}`);

  } catch (error) {
    console.error('error in deleting notification:', error);
    res.status(500).json({ message: 'error in the server' });
  }
});

// API Endpoints
app.get('/api/alerts', async (req, res) => {
  try {
    const alerts = await Alert.find().sort({ timestamp: -1 });
    res.json(alerts);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching alerts' });
  }
});

// Listen to socket connections
io.on('connection', (socket) => {
  console.log("A client connected:", socket.id);
  socket.on('disconnect', () => {
    console.log("A client disconnected:", socket.id);
  });
});


// Start server
const PORT = 8080;
const HOST = '0.0.0.0'; 

server.listen(PORT, HOST, () => {
  console.log(`Server is running at http://${HOST}:${PORT}`);
   client.subscribe('patient/location');
});

