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

// Registration Endpoint
app.post('/api/register', async (req, res) => {
  const { id, name, emailid, pass, mobile, role } = req.body;

  if (!emailid || !pass || !name) {
    return res.status(400).json({ message: 'Name, emailid, and pass are required.' });
  }

  try {
    const existingPerson = await Person.findOne({ emailid });
    if (existingPerson) {
      return res.status(400).json({ message: 'User with this emailid already exists.' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(pass, salt);

    const newPerson = await Person.create({
      id,
      name,
      emailid,
      pass: hashedPassword,
      mobile,
      role: role || 'user'
    });

    const token = jwt.sign(
      { id: newPerson._id, emailid: newPerson.emailid, role: newPerson.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(201).json({
      message: 'Registration successful',
      person: {
        _id: newPerson._id,
        id: newPerson.id,
        name: newPerson.name,
        emailid: newPerson.emailid,
        mobile: newPerson.mobile,
        role: newPerson.role
      },
      token
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`Registration Service running on port ${PORT}`));