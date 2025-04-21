 // Load environment variables from .env
require('dotenv').config();

// Required modules
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');

// Initialize Express app
const app = express();
app.use(bodyParser.json());
app.use(cors());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// User model
const UserSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
});
const User = mongoose.model('User', UserSchema);

// Patient model
const PatientSchema = new mongoose.Schema({
  fullName: String,
  dateOfBirth: String,
  diseases: String,
  safeZone: String,
  location: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
});
const Patient = mongoose.model('Patient', PatientSchema);

// Middleware for JWT verification
const verifyToken = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).send('Access denied');
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(400).send('Invalid token');
  }
};

// Route for user signup
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;

  const existingUser = await User.findOne({ email });
  if (existingUser) return res.status(400).send('Email already exists');

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, email, password: hashedPassword });

  try {
    await user.save();
    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
    res.status(201).send({ token });
  } catch (error) {
    res.status(400).send('Error creating user');
  }
});

// Route for user login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(400).send('User not found');

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).send('Invalid password');

  const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
  res.send({ token });
});

// Route for adding a new patient
app.post('/patients', verifyToken, async (req, res) => {
  const { fullName, dateOfBirth, diseases, safeZone, location } = req.body;

  const newPatient = new Patient({
    fullName,
    dateOfBirth,
    diseases,
    safeZone,
    location,
    userId: req.user._id,
  });

  try {
    await newPatient.save();
    res.status(201).send(newPatient);
  } catch (error) {
    res.status(400).send('Error adding patient');
  }
});

// Route for getting all patients of a user
app.get('/patients', verifyToken, async (req, res) => {
  try {
    const patients = await Patient.find({ userId: req.user._id });
    res.send(patients);
  } catch (error) {
    res.status(400).send('Error retrieving patients');
  }
});

// Route for getting patient info
app.get('/patients/:id', verifyToken, async (req, res) => {
  try {
    const patient = await Patient.findById(req.params.id);
    if (!patient) return res.status(404).send('Patient not found');
    res.send(patient);
  } catch (error) {
    res.status(400).send('Error retrieving patient');
  }
});

// Route for updating a patient's information
app.put('/patients/:id', verifyToken, async (req, res) => {
  try {
    const patient = await Patient.findById(req.params.id);
    if (!patient) return res.status(404).send('Patient not found');

    if (patient.userId.toString() !== req.user._id.toString()) {
      return res.status(403).send('Access denied');
    }

    Object.assign(patient, req.body);
    await patient.save();
    res.send(patient);
  } catch (error) {
    res.status(400).send('Error updating patient');
  }
});

// Route for deleting a patient
app.delete('/patients/:id', verifyToken, async (req, res) => {
  try {
    const patient = await Patient.findById(req.params.id);
    if (!patient) return res.status(404).send('Patient not found');

    if (patient.userId.toString() !== req.user._id.toString()) {
      return res.status(403).send('Access denied');
    }

    await patient.remove();
    res.status(200).send('Patient deleted');
  } catch (error) {
    res.status(400).send('Error deleting patient');
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);

});
