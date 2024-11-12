require("dotenv").config();
// Import essential modules
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs"); // Hash passwords
const jwt = require("jsonwebtoken"); // Generate tokens
const cors = require("cors");
const User = require("./Database/Users"); // User model

const app = express();

// Enable CORS for the frontend running on localhost:3000
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    methods: ["POST", "GET"],
    credentials: true,
  })
);
app.use(express.json()); // Parse JSON requests

// Connect to MongoDB database
mongoose.connect(process.env.MONGODB_URI);
// Registration Route
app.post("/new-user", async (req, res) => {
  const { name, dateOfBirth, email, password } = req.body;

  // Hash the password before saving
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({
    name,
    dateOfBirth,
    email,
    password: hashedPassword,
    normalPassword: password,
  });

  try {
    await user.save(); // Save user to database
    const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET); // Generate JWT token
    res.json({ token, user });
  } catch (error) {
    res.status(400).json({ error: "User already exists" });
  }
});

// Login Route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  // Check password match and generate token
  if (user && (await bcrypt.compare(password, user.password))) {
    const token = jwt.sign({ email: user.email }, "LoginSystem");
    res.json({ token, user });
  } else {
    res.status(400).json({ error: "Invalid credentials" });
  }
});

// Route to fetch users with selected fields for display
app.get("/users", async (req, res) => {
  try {
    const users = await User.find({}, "name dateOfBirth email normalPassword"); // Include necessary fields
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: "Server error: unable to fetch users" });
  }
});

// Start server on port 3032
app.listen(3032);
console.log("Server running on port no. 3032");
