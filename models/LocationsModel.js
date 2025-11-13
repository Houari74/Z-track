const mongoose=require('mongoose');

const locationSchema = new mongoose.Schema({
  patientId: { type: String, default: 'patient_1' },
  timestamp: { type: Date, default: Date.now },
  lat: Number,
  lon: Number,
});
module.exports= mongoose.model('Location',locationSchema);