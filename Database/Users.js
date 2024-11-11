const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  dateOfBirth: { type: Date, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },       // Hashed password
  normalPassword: { type: String, required: true }
});

module.exports = mongoose.model('RegUser', UserSchema);
