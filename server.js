const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());

/* ================= DATABASE ================= */
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

db.query("SELECT 1")
  .then(() => console.log("✅ PostgreSQL Connected"))
  .catch(err => console.error("❌ DB ERROR:", err.message));

/* ================= MAIL ================= */
/* ⚠️ Gmail may fail on Render */
const transporter = nodemailer.createTransport({
  service: "gmail", // cleaner than host config
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  }
});

/* ================= OTP ================= */
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

/* ================= SIGNUP ================= */
app.post("/signup", async (req, res) => {
  try {
    let { email, username, password } = req.body;

    if (!email || !username || !password) {
      return res.status(400).json({ success: false, message: "Missing fields" });
    }

    email = email.toLowerCase().trim();
    username = username.toLowerCase().trim();

    /* CHECK USER */
    const existing = await db.query(
      "SELECT id FROM users WHERE email=$1 OR username=$2",
      [email, username]
    );

    if (existing.rows.length > 0) {
      return res.json({ success: false, message: "User already exists" });
    }

    /* HASH PASSWORD */
    const hashedPassword = await bcrypt.hash(password, 10);

    /* INSERT USER */
    const result = await db.query(
      `INSERT INTO users (email, username, password_hash, is_verified, role)
       VALUES ($1,$2,$3,$4,$5) RETURNING id`,
      [email, username, hashedPassword, false, "intern"]
    );

    const userId = result.rows[0].id;

    /* GENERATE OTP */
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await db.query(
      "INSERT INTO otps (user_id, otp, expires_at) VALUES ($1,$2,$3)",
      [userId, otp, expiresAt]
    );

    /* SEND EMAIL (SAFE - non blocking) */
    let emailSent = true;

    try {
      await transporter.sendMail({
        from: `"OTP Service" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: "Your OTP Code",
        text: `Your OTP is ${otp}. It expires in 5 minutes.`,
      });

      console.log("📧 Email sent to:", email);
    } catch (err) {
      console.error("❌ EMAIL FAILED:", err.message);
      emailSent = false;
    }

    return res.json({
      success: true,
      message: emailSent
        ? "Signup successful! OTP sent."
        : "Signup successful! OTP generated (email failed)"
    });

  } catch (err) {
    console.error("🔥 SIGNUP ERROR:", err);

    return res.status(500).json({
      success: false,
      message: err.message
    });
  }
});

/* ================= VERIFY OTP ================= */
app.post("/verifyotp", async (req, res) => {
  try {
    let { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ success: false, message: "Missing fields" });
    }

    email = email.toLowerCase().trim();

    const userRes = await db.query(
      "SELECT id FROM users WHERE email=$1",
      [email]
    );

    if (userRes.rows.length === 0) {
      return res.json({ success: false, message: "User not found" });
    }

    const userId = userRes.rows[0].id;

    const otpRes = await db.query(
      "SELECT * FROM otps WHERE user_id=$1 AND otp=$2 AND expires_at > NOW()",
      [userId, otp]
    );

    if (otpRes.rows.length === 0) {
      return res.json({ success: false, message: "OTP invalid or expired" });
    }

    await db.query("UPDATE users SET is_verified=TRUE WHERE id=$1", [userId]);
    await db.query("DELETE FROM otps WHERE user_id=$1", [userId]);

    return res.json({ success: true, message: "Account verified!" });

  } catch (err) {
    console.error("🔥 VERIFY ERROR:", err);

    return res.status(500).json({
      success: false,
      message: err.message
    });
  }
});

/* ================= LOGIN ================= */
app.post("/login", async (req, res) => {
  try {
    let { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Missing fields" });
    }

    username = username.toLowerCase();

    const result = await db.query(
      "SELECT * FROM users WHERE email=$1 OR username=$2",
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

    return res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });

  } catch (err) {
    console.error("🔥 LOGIN ERROR:", err);

    return res.status(500).json({
      success: false,
      message: err.message
    });
  }
});


/* ================= VIDEO SYSTEM ================= */

let videos = [
  { id: 1, title: "Video 1", url: "https://effetechnology.in/Andritz_videos/Welcome1.mp4", isActive: true },
  { id: 2, title: "Video 2", url: "https://effetechnology.in/Andritz_videos/Welcome2.mp4", isActive: true },
  { id: 3, title: "Video 3", url: "", isActive: false },
  { id: 4, title: "Video 4", url: "", isActive: false },
  { id: 5, title: "Video 5", url: "", isActive: false },
  { id: 6, title: "Video 6", url: "", isActive: false },
  { id: 7, title: "Video 7", url: "", isActive: false },
  { id: 8, title: "Video 8", url: "", isActive: false },
  { id: 9, title: "Video 9", url: "", isActive: false },
  { id: 10, title: "Video 10", url: "", isActive: false }
];

function normalizeRole(role) {
  return String(role || "").toLowerCase().trim();
}

function canViewAll(role) {
  return role === "manager" || role === "hr";
}

function canViewOnlyFive(role) {
  return (
    role === "admin" ||
    role === "intern" ||
    role === "user"
  );
}

function canManageVideos(role) {
  return role === "manager" || role === "hr";
}

/* ===== GET VIDEOS ===== */
app.get("/videos/:role", (req, res) => {

  const role = normalizeRole(req.params.role);

  if (canViewAll(role)) {
    return res.json(videos);
  }

  if (canViewOnlyFive(role)) {
    return res.json(
      videos.filter(video => video.id <= 5)
    );
  }

  return res.status(403).json({
    message: "Access denied"
  });
});

/* ===== ADD VIDEO ===== */
app.post("/videos/add/:role", (req, res) => {

  const role = normalizeRole(req.params.role);

  const { url } = req.body;

  if (!canManageVideos(role)) {
    return res.status(403).json({
      message: "Only Manager and HR can add videos"
    });
  }

  if (!url || url.trim() === "") {
    return res.status(400).json({
      message: "Video URL required"
    });
  }

  const emptySlot = videos.find(
    video => video.isActive === false
  );

  if (!emptySlot) {
    return res.status(400).json({
      message: "All 10 video slots are full"
    });
  }

  emptySlot.url = url.trim();
  emptySlot.isActive = true;

  return res.json({
    success: true,
    message: "Video added",
    video: emptySlot
  });
});

/* ===== REMOVE VIDEO ===== */
app.delete("/videos/remove/:role/:id", (req, res) => {

  const role = normalizeRole(req.params.role);

  const id = Number(req.params.id);

  if (!canManageVideos(role)) {
    return res.status(403).json({
      message: "Only Manager and HR can remove videos"
    });
  }

  const video = videos.find(
    video => video.id === id
  );

  if (!video) {
    return res.status(404).json({
      message: "Video not found"
    });
  }

  video.url = "";
  video.isActive = false;

  return res.json({
    success: true,
    message: "Video removed",
    video
  });
});


/* ================= TEST ================= */
app.get("/", (req, res) => {
  res.send("Server is working ✅");
});

/* ================= SERVER ================= */
const PORT = process.env.PORT || 10000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
});