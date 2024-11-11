const mongoose = require("mongoose");

// Define User schema
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  dateOfBirth: { type: Date, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }, // Hashed password
  normalPassword: { type: String, required: true }, // Store plain password temporarily if required, but avoid in production
});

// Export the model
module.exports = mongoose.model("RegUser", UserSchema);
