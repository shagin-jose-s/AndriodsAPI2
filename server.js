const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();

/* ===== MIDDLEWARE ===== */
app.use(cors());
app.use(express.json());

/* ===== DATABASE (Render PostgreSQL) ===== */
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

/* ===== TEST DB CONNECTION ===== */
db.query("SELECT 1")
  .then(() => console.log("✅ PostgreSQL Connected"))
  .catch((err) => console.error("❌ DB Error:", err));

/* ===== MAIL SETUP ===== */
const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

/* ===== OTP FUNCTION ===== */
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

/* =====================================================
   SIGNUP
===================================================== */
app.post("/signup", async (req, res) => {
  try {
    let { email, username, password } = req.body;

    if (!email || !username || !password) {
      return res.json({ success: false, message: "Missing fields" });
    }

    email = email.toLowerCase().trim();

    const emailRegex = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/;
    if (!emailRegex.test(email)) {
      return res.json({ success: false, message: "Invalid email format" });
    }

    /* CHECK EXISTING USER */
    const existing = await db.query(
      "SELECT id FROM users WHERE email = $1 OR username = $2",
      [email, username]
    );

    if (existing.rows.length > 0) {
      return res.json({ success: false, message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    /* INSERT USER */
    const result = await db.query(
      "INSERT INTO users (email, username, password_hash, is_verified, role) VALUES ($1,$2,$3,$4,$5) RETURNING id",
      [email, username, hashedPassword, false, "intern"]
    );

    const userId = result.rows[0].id;

    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    /* SAVE OTP */
    await db.query(
      "INSERT INTO otps (user_id, otp, expires_at) VALUES ($1,$2,$3)",
      [userId, otp, expiresAt]
    );

    /* SEND EMAIL */
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your OTP Code",
      text: `Your OTP is ${otp}. It will expire in 5 minutes.`,
    });

    res.json({ success: true, message: "Signup successful! OTP sent." });

  } catch (err) {
    console.error("SIGNUP ERROR:", err);
    res.status(500).json({ success: false });
  }
});

/* =====================================================
   VERIFY OTP
===================================================== */
app.post("/verifyotp", async (req, res) => {
  try {
    let { email, otp } = req.body;

    if (!email || !otp) {
      return res.json({ success: false, message: "Missing fields" });
    }

    email = email.toLowerCase().trim();

    const userRes = await db.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (userRes.rows.length === 0) {
      return res.json({ success: false, message: "User not found" });
    }

    const userId = userRes.rows[0].id;

    const otpRes = await db.query(
      "SELECT * FROM otps WHERE user_id = $1 AND otp = $2 AND expires_at > NOW()",
      [userId, otp]
    );

    if (otpRes.rows.length === 0) {
      return res.json({ success: false, message: "OTP invalid or expired" });
    }

    await db.query(
      "UPDATE users SET is_verified = TRUE WHERE id = $1",
      [userId]
    );

    await db.query(
      "DELETE FROM otps WHERE user_id = $1",
      [userId]
    );

    res.json({ success: true, message: "Account verified!" });

  } catch (err) {
    console.error("VERIFY OTP ERROR:", err);
    res.status(500).json({ success: false });
  }
});

/* =====================================================
   LOGIN
===================================================== */
app.post("/login", async (req, res) => {
  try {
    let { username, password } = req.body;

    if (!username || !password) {
      return res.json({ success: false, message: "Missing fields" });
    }

    username = username.toLowerCase();

    const result = await db.query(
      "SELECT * FROM users WHERE email = $1 OR username = $2",
      [username, username]
    );

    if (result.rows.length === 0) {
      return res.json({ success: false, message: "Invalid credentials" });
    }

    const user = result.rows[0];

    if (!user.is_verified) {
      return res.json({ success: false, message: "User not verified yet" });
    }

    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) {
      return res.json({ success: false, message: "Invalid credentials" });
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
      },
    });

  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ success: false });
  }
});

/* ===== TEST ROUTE ===== */
app.get("/", (req, res) => {
  res.send("Server is working ✅");
});

/* ===== SERVER ===== */
const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
});