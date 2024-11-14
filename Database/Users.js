const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Name is required'],
    minlength: [3, 'Name must be at least 3 characters'],
    maxlength: [50, 'Name must be at most 50 characters'],
    trim: true,  
  },
  dateOfBirth: {
    type: Date,
    required: [true, 'Date of birth is required'],
    validate: {
      validator: function(value) {
        const today = new Date();
        return value < today;  // ensures DOB is in the past
      },
      message: 'Date of birth must be in the past',
    },
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    trim: true,
    lowercase: true,
    match: [
      /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
      'Please fill a valid email address',
    ],
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters'],
  },
  normalPassword: {
    type: String,
    required: [true, 'Normal password is required'],
    minlength: [8, 'Normal password must be at least 8 characters'],
    select: false,  // ensures this field is not returned in queries
  },
});

module.exports = mongoose.model('RegUser', UserSchema);
