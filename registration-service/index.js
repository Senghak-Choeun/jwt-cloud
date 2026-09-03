require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const connectDB = require('./db');
const User = require('./User');

const app = express();
app.use(express.json());
app.use(cors());

connectDB();

// Registration Endpoint
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: 'Please provide all required fields' });
  }

  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = await User.create({
      username,
      email,
      password: hashedPassword
    });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(201).json({
      message: 'User registered successfully',
      user: { id: user._id, username: user.username, email: user.email },
      token
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`Registration Service running on port ${PORT}`));