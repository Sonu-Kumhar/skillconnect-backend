const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
require('dotenv').config();
const Session = require('./models/Session');
const verifyToken = require('./middleware/auth');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // optional, for form data

// console.log("JWT_SECRET:", process.env.JWT_SECRET);

// MongoDB connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch((err) => console.error('❌ MongoDB error:', err));

// ================= User Schema =================
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isVerified: { type: Boolean, default: false },
  otp: { type: String },
  otpExpires: { type: Date }
});
const User = mongoose.model('User', userSchema);

// ================= Nodemailer Setup =================
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// ================= Auth Routes =================

// Schema for temporary OTP verification
// replace your current OtpVerificationSchema with this:
const OtpVerificationSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }, // hashed temp password
  otp: { type: String, required: true },
  otpExpires: { type: Date, required: true },
}, { timestamps: true });

const OtpVerification = mongoose.model('OtpVerification', OtpVerificationSchema);


// ================= Registration =================

// STEP 1: Send OTP for Registration (REPLACE your handler)
app.post('/register/send-otp', async (req, res) => {
  const { email, password } = req.body;
  try {
    // already registered?
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // upsert the OTP doc (one per email)
    await OtpVerification.findOneAndUpdate(
      { email },
      {
        password: hashedPassword,
        otp,
        otpExpires: new Date(Date.now() + 10 * 60 * 1000)
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    await transporter.sendMail({
      from: `"SkillConnect Team" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "SkillConnect - Verify your account",
      text: `Your OTP is ${otp}. It is valid for 10 minutes.`,
      html: `<p>Hello,</p>
         <p>Your OTP is <b>${otp}</b>. It is valid for 10 minutes.</p>
         <p>Thank you for using <b>SkillConnect</b> 🚀</p>`
    });


    res.status(201).json({ message: 'OTP sent to email' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Verify OTP and create user
// STEP 2: Verify OTP and create user (REPLACE your handler)
// Verify OTP and create user
app.post('/register/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  try {
    const record = await OtpVerification.findOne({ email });
    if (!record) {
      return res.status(404).json({ message: 'No OTP request found for this email' });
    }

    // compare strings safely
    if ((record.otp || '').trim() !== String(otp).trim()) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    if (new Date() > new Date(record.otpExpires)) {
      return res.status(400).json({ message: 'OTP expired' });
    }

    // create the verified user
    const newUser = await User.create({
      email: record.email,
      password: record.password, // already hashed
      isVerified: true,
    });

    // remove the temp OTP doc
    await OtpVerification.deleteOne({ email });

    // ✅ Generate JWT token right after registration
    const token = jwt.sign(
      { id: newUser._id },
      process.env.JWT_SECRET || "secret_key",
      { expiresIn: "1h" }
    );

    return res.json({
      success: true,
      message: "Account created successfully!",
      token, // 🔑 return token so frontend can auto-login
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});


app.get('/ping', (req, res) => {
  res.send('pong');
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (!user.isVerified) {
      return res.status(403).json({ message: 'Please verify your email first' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET || 'secret_key',
      { expiresIn: '1h' }
    );

    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});



// STEP 1: Send OTP
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.otp = otp;
    user.otpExpires = Date.now() + 10 * 60 * 1000;
    await user.save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Reset your password - SkillConnect',
      text: `Your password reset OTP is ${otp}. It is valid for 10 minutes.`,
    });

    res.json({ message: 'Password reset OTP sent to email' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// STEP 2: Verify OTP
app.post('/forgot-password/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (user.otp !== otp || user.otpExpires < Date.now()) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    res.json({ success: true, message: 'OTP verified, you can reset password now' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// STEP 3: Reset Password
app.post('/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.otp = null;
    user.otpExpires = null;
    await user.save();

    res.json({ success: true, message: 'Password reset successfully!' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});



// Publish session
app.post('/my-sessions/publish', verifyToken, async (req, res) => {
  const { title, description, duration, date, time, mode, meetingLink, location, mentor } = req.body;

  try {
    const newSession = new Session({
      title,
      description,
      duration,
      date,
      time,
      mode: mode || 'offline',  //default to offline
      meetingLink: mode === 'online' ? meetingLink : null,
      location: mode === 'offline' ? location : null,
      mentor,
      status: 'published',
      userId: req.userId,
    });

    await newSession.save();
    res.status(201).json({ message: 'Session published successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error publishing session' });
  }
});

// Save draft
app.post('/my-sessions/save-draft', verifyToken, async (req, res) => {
  const { title, description, duration, date, time, mode, meetingLink, location, mentor } = req.body;

  try {
    const newSession = new Session({
      title,
      description,
      duration,
      date,
      time,
      mode: mode || 'offline',  //default to offline
      meetingLink: mode === 'online' ? meetingLink : null,
      location: mode === 'offline' ? location : null,
      mentor,
      status: 'draft',
      userId: req.userId,
    });

    await newSession.save();
    res.status(201).json({ message: 'Session draft saved successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error saving draft' });
  }
});

app.get('/my-sessions', verifyToken, async (req, res) => {
  try {
    const sessions = await Session.find({ userId: req.userId });
    res.json(sessions);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch sessions' });
  }
});

// Login Route
// app.post('/login', async (req, res) => {
//   const { email, password } = req.body;

//   try {
//     const user = await User.findOne({ email });
//     if (!user) {
//       return res.status(404).json({ message: 'User not found' });
//     }

//     const isMatch = await bcrypt.compare(password, user.password);
//     if (!isMatch) {
//       return res.status(401).json({ message: 'Invalid credentials' });
//     }

//     const token = jwt.sign(
//       { id: user._id },
//       process.env.JWT_SECRET || 'secret_key',
//       { expiresIn: '1h' }
//     );

//     res.json({ token });
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ message: 'Server error' });
//   }
// });

// Public Sessions Route
app.get('/sessions', async (req, res) => {
  try {
    const sessions = await Session.find({ status: 'published' });
    res.json(sessions);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/my-sessions/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const deleted = await Session.findOneAndDelete({ _id: id, userId: req.userId });
    if (!deleted) {
      return res.status(404).json({ message: 'Session not found or unauthorized' });
    }
    res.json({ message: 'Session deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting session' });
  }
});

// ✅ Update session
app.put('/my-sessions/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  const { title, description, duration, date, time, mode, meetingLink, location, mentor, status } = req.body;

  try {
    const session = await Session.findOneAndUpdate(
      { _id: id, userId: req.userId },
      {
        title,
        description,
        duration,
        date,
        time,
        mode: mode || 'offline',
        meetingLink: mode === 'online' ? meetingLink : null,
        location: mode === 'offline' ? location : null,
        mentor,
        status,
        updated_at: Date.now()
      },
      { new: true }
    );

    if (!session) {
      return res.status(404).json({ message: 'Session not found or unauthorized' });
    }

    res.json({ message: 'Session updated successfully', session });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error updating session' });
  }
});

/**
 * ✅ Register for a published session
 * - Auth required
 * - Prevents duplicate registrations
 * - Updates registeredUsers[] and registeredCount
 * - Returns updated count
 */
app.post('/sessions/:id/register', verifyToken, async (req, res) => {
  const { id } = req.params;

  try {
    const session = await Session.findById(id);
    if (!session) {
      return res.status(404).json({ message: 'Session not found' });
    }

    if (session.status !== 'published') {
      return res.status(400).json({ message: 'Only published sessions are open for registration' });
    }

    // Prevent duplicate registrations
    const already = session.registeredUsers?.some(
      (u) => u.toString() === req.userId
    );
    if (already) {
      return res.status(400).json({ message: 'Already registered' });
    }

    // Push user & update count
    session.registeredUsers = session.registeredUsers || [];
    session.registeredUsers.push(req.userId);
    session.registeredCount = session.registeredUsers.length;

    await session.save();

    return res.json({
      message: 'Successfully registered',
      count: session.registeredCount,
      sessionId: session._id
    });

  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ message: 'Error registering for session' });
  }
});

// ✅ Get registration count
app.get('/sessions/:id/registrations', async (req, res) => {
  try {
    const session = await Session.findById(req.params.id).populate('registeredUsers', 'name email');
    if (!session) return res.status(404).json({ message: 'Session not found' });

    res.json({
      registrationCount: session.registeredUsers.length,
      users: session.registeredUsers,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

mongoose.connection.on('connected', () => {
  console.log(`✅ Connected to MongoDB database: ${mongoose.connection.name}`);
});
