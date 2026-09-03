require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const connectDB = require('./db');
const Person = require('./person.schema');

const app = express();
app.use(express.json());
app.use(cors());

connectDB();

// Login Endpoint
app.post('/api/login', async (req, res) => {
  const { emailid, pass } = req.body;

  if (!emailid || !pass) {
    return res.status(400).json({ message: 'Please provide emailid and pass' });
  }

  try {
    const person = await Person.findOne({ emailid });
    if (!person) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(pass, person.pass);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: person._id, emailid: person.emailid, role: person.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(200).json({
      message: 'Login successful',
      person: {
        _id: person._id,
        id: person.id,
        name: person.name,
        emailid: person.emailid,
        role: person.role
      },
      token
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

const PORT = process.env.PORT || 5002;
app.listen(PORT, () => console.log(`Authentication Service running on port ${PORT}`));