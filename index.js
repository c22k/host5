const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const dotenv = require("dotenv")

const app = express();

// Enable CORS
app.use(cors());

// Body parsing middleware
app.use(express.json());

// MongoDB connection
dotenv.config({path:'./config.env'});
const DB = process.env.DATABASE
const PORT = process.env.PORT || 4000;


mongoose.connect(DB).then(() => {
  console.log('Connection Successful');
}).catch((err) => console.log('No connection'));

// User model
const User = mongoose.model('User', {
  email: String,
  password: String,
  resetToken: String,
  resetTokenExpiration: Date,
});

// Configure Nodemailer with your email service provider
const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: 'ckn6489@gmail.com',
    pass: 'yuhqozvdlfybtwzl',
  },
});

// Registration endpoint
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      email,
      password: hashedPassword,
    });

    await user.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      res.status(401).json({ message: 'Invalid email or password' });
      return;
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      res.status(401).json({ message: 'Invalid email or password' });
      return;
    }

    const token = jwt.sign({ email }, 'secret_key');

    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Password reset request endpoint
app.post('/request-reset', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      res.status(404).json({ message: 'User not found' });
      return;
    }

    const resetToken = jwt.sign({ email }, 'reset_secret_key', { expiresIn: '1h' });
    user.resetToken = resetToken;
    user.resetTokenExpiration = Date.now() + 3600000; // 1 hour
    await user.save();

    // Send the reset token to the user's email
    const mailOptions = {
      from: 'ckn6489@gmail.com',
      to: email,
      subject: 'Password Reset',
      html: `<p>You requested a password reset. Click <a href="http://localhost:3000/${resetToken}">here</a> to reset your password.</p>`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error(error);
        res.status(500).json({ message: 'Error sending email' });
      } else {
        console.log('Email sent:', info.response);
        res.json({ message: 'Password reset email sent' });
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Password reset endpoint
app.post('/reset-password', async (req, res) => {
  const { resetToken, newPassword } = req.body;

  try {
    const user = await User.findOne({ resetToken });

    if (!user || user.resetTokenExpiration < Date.now()) {
      res.status(401).json({ message: 'Invalid or expired reset token' });
      return;
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;
    user.resetToken = null;
    user.resetTokenExpiration = null;
    await user.save();

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
if (process.env.NODE_ENV === "production") {
  // Serve static files from the "client" directory
  app.use(express.static("build"));

  // For any request that doesn't match a static file, serve the index.html file
  app.get("*", (req, res) => {
    res.sendFile(path.resolve(__dirname, "build", "index.html"));
  });
}

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
