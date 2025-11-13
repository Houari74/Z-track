const mongoose=require('mongoose');
// Define a schema for alerts
const alertSchema = new mongoose.Schema({
  patientId: { type: String, default: 'patient_1' },
  timestamp: { type: Date, default: Date.now },
  message: String,
},
{ timestamps: true });
module.exports= mongoose.model('Alert',alertSchema);
