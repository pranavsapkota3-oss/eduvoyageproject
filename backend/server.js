import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import { db } from "./db.js";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// ✅ middleware
app.use(
  cors({
    origin: ["http://localhost:5173", "http://localhost:5174", "http://localhost:5175", "http://localhost:5176", "http://localhost:5177"],
    credentials: true,
  })
);
app.use(express.json());


// ✅ middleware
app.use(
  cors({
    origin: ["http://localhost:5173", "http://localhost:5174", "http://localhost:5175", "http://localhost:5176", "http://localhost:5177"],
    credentials: true,
  })
);
app.use(express.json());

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD,
  },
});

const generateOtp = () => String(Math.floor(100000 + Math.random() * 900000));

const sendOtpEmail = async (email, code) => {
  await transporter.sendMail({
    from: `EduVoyage <${process.env.GMAIL_USER}>`,
    to: email,
    subject: "Your EduVoyage verification code",
    text: `Your verification code is ${code}. It expires in 10 minutes.`,
  });
};

const sendResetEmail = async (email, code) => {
  await transporter.sendMail({
    from: `EduVoyage <${process.env.GMAIL_USER}>`,
    to: email,
    subject: "EduVoyage password reset code",
    text: `Your password reset code is ${code}. It expires in 10 minutes.`,
  });
};

const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const safeName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_");
    const unique = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    cb(null, `${unique}-${safeName}`);
  },
});

const upload = multer({ storage });

app.use("/uploads", express.static(uploadsDir));

const countryImages = {
  USA: "https://images.unsplash.com/photo-1523050854058-8df90110c9f1?w=1200&h=800&fit=crop",
  Canada: "https://images.unsplash.com/photo-1507537297725-24a1c029d3ca?w=1200&h=800&fit=crop",
  Australia: "https://images.unsplash.com/photo-1519451241324-20b4ea2c4220?w=1200&h=800&fit=crop",
  UK: "https://images.unsplash.com/photo-1469474968028-56623f02e42e?w=1200&h=800&fit=crop",
};

const buildSeedUniversities = () => {
  const base = [
    { name: "Massachusetts Institute of Technology (MIT)", country: "USA", city: "Cambridge", website: "https://www.mit.edu" },
    { name: "Stanford University", country: "USA", city: "Stanford", website: "https://www.stanford.edu" },
    { name: "Harvard University", country: "USA", city: "Cambridge", website: "https://www.harvard.edu" },
    { name: "University of Cambridge", country: "UK", city: "Cambridge", website: "https://www.cam.ac.uk" },
    { name: "University of Oxford", country: "UK", city: "Oxford", website: "https://www.ox.ac.uk" },
    { name: "University of Toronto", country: "Canada", city: "Toronto", website: "https://www.utoronto.ca" },
    { name: "McGill University", country: "Canada", city: "Montreal", website: "https://www.mcgill.ca" },
    { name: "University of Melbourne", country: "Australia", city: "Melbourne", website: "https://www.unimelb.edu.au" },
    { name: "Australian National University (ANU)", country: "Australia", city: "Canberra", website: "https://www.anu.edu.au" },
    { name: "University of Sydney", country: "Australia", city: "Sydney", website: "https://www.sydney.edu.au" },
  ];

  const usStates = [
    "California", "Texas", "Florida", "New York", "Illinois", "Pennsylvania", "Ohio", "Georgia", "Michigan", "Virginia",
    "North Carolina", "Washington", "Arizona", "Massachusetts", "Indiana", "Tennessee", "Missouri", "Maryland", "Colorado", "Wisconsin",
    "Minnesota", "South Carolina", "Alabama", "Louisiana", "Kentucky", "Oregon", "Oklahoma", "Connecticut", "Iowa", "Utah",
    "Nevada", "Kansas", "Arkansas", "Mississippi", "Nebraska",
  ];
  const ukCities = [
    "London", "Manchester", "Birmingham", "Leeds", "Bristol", "Glasgow", "Edinburgh", "Cardiff", "Belfast", "Newcastle",
    "Sheffield", "Nottingham", "Leicester", "Coventry", "Liverpool", "Southampton", "Portsmouth", "Exeter", "Bath", "York",
    "Reading", "Durham", "Lancaster", "Swansea", "St Andrews",
  ];
  const canadaCities = [
    "Vancouver", "Ottawa", "Calgary", "Edmonton", "Quebec City", "Winnipeg", "Halifax", "Saskatoon", "Victoria", "Hamilton",
    "London", "Waterloo", "Kingston", "Montreal", "Toronto", "Regina", "Guelph", "Kelowna", "Burnaby", "Sherbrooke",
    "Sudbury", "Moncton", "St. John's",
  ];
  const australiaCities = [
    "Sydney", "Melbourne", "Brisbane", "Perth", "Adelaide", "Canberra", "Hobart", "Gold Coast", "Newcastle", "Wollongong",
    "Geelong", "Townsville", "Cairns", "Darwin", "Launceston", "Sunshine Coast", "Canberra", "Ballarat", "Bendigo", "Albury",
    "Toowoomba", "Bundaberg",
  ];

  const generated = [];
  usStates.forEach((state) => {
    generated.push({ name: `University of ${state}`, country: "USA", city: state, website: "" });
    generated.push({ name: `${state} State University`, country: "USA", city: state, website: "" });
  });
  ukCities.forEach((city) => {
    generated.push({ name: `University of ${city}`, country: "UK", city, website: "" });
  });
  canadaCities.forEach((city) => {
    generated.push({ name: `University of ${city}`, country: "Canada", city, website: "" });
  });
  australiaCities.forEach((city) => {
    generated.push({ name: `University of ${city}`, country: "Australia", city, website: "" });
  });

  const combined = [...base, ...generated].slice(0, 150);
  return combined.map((item, index) => ({
    ...item,
    ranking: index + 1,
    overview: `${item.name} is a leading institution in ${item.country}, known for strong academics and global research.`,
    courses: "Engineering, Business, Computer Science, Health Sciences, Arts & Humanities.",
    fees: item.country === "USA" ? "USD 28,000 - 55,000 per year"
      : item.country === "UK" ? "GBP 18,000 - 38,000 per year"
      : item.country === "Canada" ? "CAD 18,000 - 35,000 per year"
      : "AUD 22,000 - 45,000 per year",
    facilities: "Modern labs, libraries, career center, on-campus housing, sports facilities.",
    scholarships: "Merit-based and need-based scholarships available for international students.",
    admissions: "Online application, transcripts, English proficiency test, statement of purpose.",
    location: `${item.city}, ${item.country}`,
    contact: "admissions@eduvoyage.edu | +1 555-0123",
    image_url: countryImages[item.country] || countryImages.USA,
  }));
};

const seedUniversities = async () => {
  try {
    const [rows] = await db.query("SELECT COUNT(*) AS count FROM universities");
    if (rows[0].count > 0) return;

    const seed = buildSeedUniversities();
    const values = seed.map((u) => [
      u.name,
      u.country,
      u.city,
      u.ranking,
      u.website,
      u.overview,
      u.courses,
      u.fees,
      u.facilities,
      u.scholarships,
      u.admissions,
      u.location,
      u.contact,
      u.image_url,
    ]);

    await db.query(
      `INSERT INTO universities
        (name, country, city, ranking, website, overview, courses, fees, facilities, scholarships, admissions, location, contact, image_url)
       VALUES ?`,
      [values]
    );
  } catch (err) {
    console.error("UNIVERSITY SEED ERROR:", err);
  }
};

// ✅ base route (fixes "Cannot GET /")
app.get("/", (req, res) => {
  res.json({ message: "EduVoyage backend running" });
});

// ✅ Debug env
app.get("/api/debug/env", (req, res) => {
  res.json({
    hasJwtSecret: !!process.env.JWT_SECRET,
    jwtSecretLength: process.env.JWT_SECRET ? process.env.JWT_SECRET.length : 0,
    dbUser: process.env.DB_USER,
    dbName: process.env.DB_NAME,
  });
});


// ✅ MySQL health check
app.get("/api/health/db", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT 1 + 1 AS result");
    res.json({ ok: true, db: true, result: rows[0].result });
  } catch (err) {
    console.error("DB HEALTH ERROR:", err);
    res.status(500).json({ ok: false, db: false, error: err.message });
  }
});

// ✅ JWT Middleware
const authMiddleware = (req, res, next) => {
  const header = req.headers.authorization;
  const token = header?.startsWith("Bearer ") ? header.split(" ")[1] : null;

  if (!token) return res.status(401).json({ message: "Missing token" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid token" });
  }
};

const requireAdmin = async (req, res, next) => {
  try {
    const [rows] = await db.query(
      "SELECT role, is_active FROM users WHERE id = ?",
      [req.user.id]
    );

    if (rows.length === 0) {
      return res.status(403).json({ message: "Access denied" });
    }

    if (!rows[0].is_active) {
      return res.status(403).json({ message: "Account is inactive" });
    }

    if (rows[0].role !== "admin") {
      return res.status(403).json({ message: "Admin access required" });
    }

    next();
  } catch (err) {
    console.error("ADMIN CHECK ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
};

const requireAgent = async (req, res, next) => {
  try {
    const [rows] = await db.query(
      "SELECT role, is_active FROM users WHERE id = ?",
      [req.user.id]
    );

    if (rows.length === 0) {
      return res.status(403).json({ message: "Access denied" });
    }

    if (!rows[0].is_active) {
      return res.status(403).json({ message: "Account is inactive" });
    }

    if (rows[0].role !== "agent") {
      return res.status(403).json({ message: "Agent access required" });
    }

    next();
  } catch (err) {
    console.error("AGENT CHECK ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
};

const requireAgentOrAdmin = async (req, res, next) => {
  try {
    const [rows] = await db.query(
      "SELECT role, is_active FROM users WHERE id = ?",
      [req.user.id]
    );

    if (rows.length === 0) {
      return res.status(403).json({ message: "Access denied" });
    }

    if (!rows[0].is_active) {
      return res.status(403).json({ message: "Account is inactive" });
    }

    if (rows[0].role !== "agent" && rows[0].role !== "admin") {
      return res.status(403).json({ message: "Agent access required" });
    }

    next();
  } catch (err) {
    console.error("AGENT CHECK ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
};

// ✅ SIGNUP
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { full_name, email, password } = req.body;

    if (!full_name || !email || !password) {
      return res
        .status(400)
        .json({ message: "full_name, email, password are required" });
    }

    const [exists] = await db.query("SELECT id FROM users WHERE email = ?", [
      email,
    ]);
    if (exists.length > 0) {
      return res.status(409).json({ message: "Email already registered" });
    }

    const password_hash = await bcrypt.hash(password, 10);

    const otpCode = generateOtp();

    await db.query(
      `INSERT INTO signup_otps (email, full_name, password_hash, otp_code, otp_expires_at)
       VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE))
       ON DUPLICATE KEY UPDATE
         full_name = VALUES(full_name),
         password_hash = VALUES(password_hash),
         otp_code = VALUES(otp_code),
         otp_expires_at = VALUES(otp_expires_at)`,
      [email, full_name, password_hash, otpCode]
    );

    await sendOtpEmail(email, otpCode);

    return res.status(201).json({
      message: "OTP sent to your email. Please verify to complete signup.",
    });
  } catch (err) {
    console.error("SIGNUP ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});

// バ. VERIFY OTP
app.post("/api/auth/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ message: "email and otp are required" });
    }

    const [rows] = await db.query(
      `SELECT email, full_name, password_hash
       FROM signup_otps
       WHERE email = ? AND otp_code = ? AND otp_expires_at > NOW()`,
      [email, otp]
    );

    if (rows.length === 0) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    const record = rows[0];

    const [result] = await db.query(
      "INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)",
      [record.full_name, record.email, record.password_hash]
    );

    await db.query("DELETE FROM signup_otps WHERE email = ?", [email]);

    return res.json({ message: "Email verified. You can now log in.", userId: result.insertId });
  } catch (err) {
    console.error("VERIFY OTP ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});

// バ. RESEND OTP
app.post("/api/auth/resend-otp", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ message: "email is required" });
    }

    const [rows] = await db.query(
      "SELECT email FROM signup_otps WHERE email = ?",
      [email]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "No pending signup found" });
    }

    const otpCode = generateOtp();

    await db.query(
      `UPDATE signup_otps
       SET otp_code = ?, otp_expires_at = DATE_ADD(NOW(), INTERVAL 10 MINUTE)
       WHERE email = ?`,
      [otpCode, email]
    );

    await sendOtpEmail(email, otpCode);

    return res.json({ message: "OTP resent to your email." });
  } catch (err) {
    console.error("RESEND OTP ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});

// ƒo. FORGOT PASSWORD (send reset code)
app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ message: "email is required" });
    }

    const [users] = await db.query("SELECT id FROM users WHERE email = ?", [email]);
    if (users.length === 0) {
      return res.json({ message: "If the email exists, a reset code has been sent." });
    }

    const resetCode = generateOtp();

    await db.query(
      `INSERT INTO password_resets (email, otp_code, otp_expires_at)
       VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE))
       ON DUPLICATE KEY UPDATE
         otp_code = VALUES(otp_code),
         otp_expires_at = VALUES(otp_expires_at)`,
      [email, resetCode]
    );

    await sendResetEmail(email, resetCode);

    return res.json({ message: "Reset code sent to your email." });
  } catch (err) {
    console.error("FORGOT PASSWORD ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});

// ƒo. RESET PASSWORD (verify code + update)
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { email, otp, new_password } = req.body;
    if (!email || !otp || !new_password) {
      return res.status(400).json({ message: "email, otp, new_password are required" });
    }

    const [rows] = await db.query(
      `SELECT email
       FROM password_resets
       WHERE email = ? AND otp_code = ? AND otp_expires_at > NOW()`,
      [email, otp]
    );

    if (rows.length === 0) {
      return res.status(400).json({ message: "Invalid or expired code" });
    }

    const password_hash = await bcrypt.hash(new_password, 10);
    await db.query("UPDATE users SET password_hash = ? WHERE email = ?", [
      password_hash,
      email,
    ]);

    await db.query("DELETE FROM password_resets WHERE email = ?", [email]);

    return res.json({ message: "Password updated. You can now log in." });
  } catch (err) {
    console.error("RESET PASSWORD ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});

// ✅ LOGIN
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "email and password are required" });
    }

    const [rows] = await db.query(
      "SELECT id, full_name, email, password_hash, role, is_active FROM users WHERE email = ?",
      [email]
    );

    if (rows.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = rows[0];

    if (!user.is_active) {
      return res.status(403).json({ message: "Account is inactive" });
    }

    if (!user.password_hash) {
      return res.status(500).json({
        message: "Server error",
        details: "password_hash missing for this user. Re-signup user.",
      });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    if (!process.env.JWT_SECRET) {
      return res.status(500).json({
        message: "Server error",
        details: "JWT_SECRET missing in .env",
      });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, full_name: user.full_name, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.json({
      message: "Login successful",
      token,
      user: { id: user.id, full_name: user.full_name, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});

// ƒo. AGENT USERS LIST
app.get("/api/admin/users", authMiddleware, requireAdmin, async (req, res) => {
  try {
    const { search = "", role = "", active = "" } = req.query;
    const filters = [];
    const params = [];

    if (search) {
      filters.push("(full_name LIKE ? OR email LIKE ?)");
      params.push(`%${search}%`, `%${search}%`);
    }
    if (role) {
      filters.push("role = ?");
      params.push(role);
    }
    if (active !== "") {
      filters.push("is_active = ?");
      params.push(active === "1" ? 1 : 0);
    }

    const whereClause = filters.length ? `WHERE ${filters.join(" AND ")}` : "";

    const [rows] = await db.query(
      `SELECT id, full_name, email, role, is_active, created_at
       FROM users
       ${whereClause}
       ORDER BY created_at DESC
       LIMIT 200`,
      params
    );

    return res.json({ users: rows });
  } catch (err) {
    console.error("ADMIN LIST ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});

// ƒo. ADMIN UPDATE ROLE
app.patch("/api/admin/users/:id/role", authMiddleware, requireAdmin, async (req, res) => {
  try {
    const { role } = req.body;
    const allowedRoles = ["student", "agent", "admin"];
    if (!role) {
      return res.status(400).json({ message: "role is required" });
    }
    if (!allowedRoles.includes(role)) {
      return res.status(400).json({ message: "Invalid role" });
    }
    await db.query("UPDATE users SET role = ? WHERE id = ?", [role, req.params.id]);
    return res.json({ message: "Role updated" });
  } catch (err) {
    console.error("ADMIN ROLE ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});

// ƒo. ADMIN UPDATE STATUS
app.patch("/api/admin/users/:id/status", authMiddleware, requireAdmin, async (req, res) => {
  try {
    const { is_active } = req.body;
    await db.query("UPDATE users SET is_active = ? WHERE id = ?", [
      is_active ? 1 : 0,
      req.params.id,
    ]);
    return res.json({ message: "Status updated" });
  } catch (err) {
    console.error("ADMIN STATUS ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});

// ƒo. ADMIN DELETE USER
app.delete("/api/admin/users/:id", authMiddleware, requireAdmin, async (req, res) => {
  try {
    await db.query("DELETE FROM users WHERE id = ?", [req.params.id]);
    return res.json({ message: "User deleted" });
  } catch (err) {
    console.error("ADMIN DELETE ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});

// ƒo. PUBLIC UNIVERSITIES LIST
app.get("/api/universities", async (req, res) => {
  try {
    const page = Math.max(1, Number(req.query.page || 1));
    const limit = Math.max(1, Math.min(10, Number(req.query.limit || 10)));
    const offset = (page - 1) * limit;
    const q = String(req.query.q || "").trim();

    const whereClause = q ? "WHERE name LIKE ? OR country LIKE ? OR city LIKE ?" : "";
    const params = q ? [`%${q}%`, `%${q}%`, `%${q}%`] : [];

    const [[countRow]] = await db.query(
      `SELECT COUNT(*) AS total FROM universities ${whereClause}`,
      params
    );
    const total = countRow.total || 0;

    const [rows] = await db.query(
      `SELECT id, name, country, city, ranking, website, image_url
       FROM universities
       ${whereClause}
       ORDER BY ranking IS NULL, ranking ASC, name ASC
       LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    return res.json({ universities: rows, total, page, limit });
  } catch (err) {
    console.error("UNIVERSITIES LIST ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});

app.get("/api/universities/:id", async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT id, name, country, city, ranking, website, overview, courses, fees,
              facilities, scholarships, admissions, location, contact, image_url
       FROM universities
       WHERE id = ?`,
      [req.params.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "University not found" });
    }

    return res.json({ university: rows[0] });
  } catch (err) {
    console.error("UNIVERSITY DETAIL ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});

// ƒo. AGENT ADD UNIVERSITY
app.post("/api/agent/universities", authMiddleware, requireAgentOrAdmin, async (req, res) => {
  try {
    const {
      name,
      country,
      city,
      ranking,
      website,
      overview,
      courses,
      fees,
      facilities,
      scholarships,
      admissions,
      location,
      contact,
      image_url,
    } = req.body;

    if (!name || !country) {
      return res.status(400).json({ message: "name and country are required" });
    }

    await db.query(
      `INSERT INTO universities
        (name, country, city, ranking, website, overview, courses, fees, facilities, scholarships, admissions, location, contact, image_url)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        name,
        country,
        city || null,
        ranking || null,
        website || null,
        overview || null,
        courses || null,
        fees || null,
        facilities || null,
        scholarships || null,
        admissions || null,
        location || null,
        contact || null,
        image_url || null,
      ]
    );

    return res.status(201).json({ message: "University added" });
  } catch (err) {
    console.error("ADD UNIVERSITY ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});

app.patch("/api/agent/universities/:id", authMiddleware, requireAgentOrAdmin, async (req, res) => {
  try {
    const {
      name,
      country,
      city,
      ranking,
      website,
      overview,
      courses,
      fees,
      facilities,
      scholarships,
      admissions,
      location,
      contact,
      image_url,
    } = req.body;

    await db.query(
      `UPDATE universities
       SET name = ?, country = ?, city = ?, ranking = ?, website = ?, overview = ?, courses = ?, fees = ?,
           facilities = ?, scholarships = ?, admissions = ?, location = ?, contact = ?, image_url = ?
       WHERE id = ?`,
      [
        name,
        country,
        city || null,
        ranking || null,
        website || null,
        overview || null,
        courses || null,
        fees || null,
        facilities || null,
        scholarships || null,
        admissions || null,
        location || null,
        contact || null,
        image_url || null,
        req.params.id,
      ]
    );

    return res.json({ message: "University updated" });
  } catch (err) {
    console.error("UPDATE UNIVERSITY ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});

app.delete("/api/agent/universities/:id", authMiddleware, requireAdmin, async (req, res) => {
  try {
    await db.query("DELETE FROM universities WHERE id = ?", [req.params.id]);
    return res.json({ message: "University deleted" });
  } catch (err) {
    console.error("DELETE UNIVERSITY ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});

// ✅ Protected example route (frontend can call this after login)
app.get("/api/profile", authMiddleware, (req, res) => {
  res.json({
    message: "Profile fetched",
    user: req.user,
  });
});

// ✅ start server
// ?. Get personal profile info
app.get("/api/profile/personal", authMiddleware, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT u.id, u.full_name, u.email, p.dob, p.gender, p.country, p.nationality, p.city
       FROM users u
       LEFT JOIN user_profiles p ON p.user_id = u.id
       WHERE u.id = ?`,
      [req.user.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.json({ profile: rows[0] });
  } catch (err) {
    console.error("GET PERSONAL PROFILE ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});

// ?. Update personal profile info
app.put("/api/profile/personal", authMiddleware, async (req, res) => {
  try {
    const { full_name, dob, gender, country, nationality, city } = req.body;

    if (full_name) {
      await db.query("UPDATE users SET full_name = ? WHERE id = ?", [
        full_name,
        req.user.id,
      ]);
    }

    await db.query(
      `INSERT INTO user_profiles (user_id, dob, gender, country, nationality, city)
       VALUES (?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         dob = VALUES(dob),
         gender = VALUES(gender),
         country = VALUES(country),
         nationality = VALUES(nationality),
         city = VALUES(city)`,
      [
        req.user.id,
        dob || null,
        gender || null,
        country || null,
        nationality || null,
        city || null,
      ]
    );

    return res.json({ message: "Personal profile updated" });
  } catch (err) {
    console.error("UPDATE PERSONAL PROFILE ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});

// ?. Get academic background info
app.get("/api/profile/academic", authMiddleware, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT highest_level, gpa, school_name, graduation_year, field_of_study,
              ielts_score, toefl_score, gre_score, gmat_score
       FROM user_academics
       WHERE user_id = ?`,
      [req.user.id]
    );

    return res.json({ academic: rows[0] || null });
  } catch (err) {
    console.error("GET ACADEMIC PROFILE ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});

// ?. Update academic background info
app.put("/api/profile/academic", authMiddleware, async (req, res) => {
  try {
    const {
      highest_level,
      gpa,
      school_name,
      graduation_year,
      field_of_study,
      ielts_score,
      toefl_score,
      gre_score,
      gmat_score,
    } = req.body;

    await db.query(
      `INSERT INTO user_academics
        (user_id, highest_level, gpa, school_name, graduation_year, field_of_study,
         ielts_score, toefl_score, gre_score, gmat_score)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         highest_level = VALUES(highest_level),
         gpa = VALUES(gpa),
         school_name = VALUES(school_name),
         graduation_year = VALUES(graduation_year),
         field_of_study = VALUES(field_of_study),
         ielts_score = VALUES(ielts_score),
         toefl_score = VALUES(toefl_score),
         gre_score = VALUES(gre_score),
         gmat_score = VALUES(gmat_score)`,
      [
        req.user.id,
        highest_level || null,
        gpa || null,
        school_name || null,
        graduation_year || null,
        field_of_study || null,
        ielts_score || null,
        toefl_score || null,
        gre_score || null,
        gmat_score || null,
      ]
    );

    return res.json({ message: "Academic background updated" });
  } catch (err) {
    console.error("UPDATE ACADEMIC PROFILE ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});

// ?. Get study preferences
app.get("/api/profile/preferences", authMiddleware, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT degree_level, field_of_study, preferred_countries, annual_budget, preferred_intake
       FROM user_preferences
       WHERE user_id = ?`,
      [req.user.id]
    );

    return res.json({ preferences: rows[0] || null });
  } catch (err) {
    console.error("GET STUDY PREFERENCES ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});

// ?. Update study preferences
app.put("/api/profile/preferences", authMiddleware, async (req, res) => {
  try {
    const {
      degree_level,
      field_of_study,
      preferred_countries,
      annual_budget,
      preferred_intake,
    } = req.body;

    await db.query(
      `INSERT INTO user_preferences
        (user_id, degree_level, field_of_study, preferred_countries, annual_budget, preferred_intake)
       VALUES (?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         degree_level = VALUES(degree_level),
         field_of_study = VALUES(field_of_study),
         preferred_countries = VALUES(preferred_countries),
         annual_budget = VALUES(annual_budget),
         preferred_intake = VALUES(preferred_intake)`,
      [
        req.user.id,
        degree_level || null,
        field_of_study || null,
        preferred_countries || null,
        annual_budget || null,
        preferred_intake || null,
      ]
    );

    return res.json({ message: "Study preferences updated" });
  } catch (err) {
    console.error("UPDATE STUDY PREFERENCES ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});

// ?. Get documents list
app.get("/api/profile/documents", authMiddleware, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT id, file_name, file_size, file_url, mime_type, created_at
       FROM user_documents
       WHERE user_id = ?
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    return res.json({ documents: rows });
  } catch (err) {
    console.error("GET DOCUMENTS ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});

// ?. Add documents
app.post(
  "/api/profile/documents",
  authMiddleware,
  upload.array("documents", 10),
  async (req, res) => {
    try {
      const files = req.files || [];

      if (files.length === 0) {
        return res.status(400).json({ message: "No documents provided" });
      }

      const values = files.map((file) => [
        req.user.id,
        file.originalname || "Document",
        `${(file.size / (1024 * 1024)).toFixed(2)} MB`,
        `/uploads/${file.filename}`,
        file.mimetype || null,
      ]);

      await db.query(
        "INSERT INTO user_documents (user_id, file_name, file_size, file_url, mime_type) VALUES ?",
        [values]
      );

      const [rows] = await db.query(
        `SELECT id, file_name, file_size, file_url, mime_type, created_at
         FROM user_documents
         WHERE user_id = ?
         ORDER BY created_at DESC`,
        [req.user.id]
      );

      return res.json({ message: "Documents saved", documents: rows });
    } catch (err) {
      console.error("ADD DOCUMENTS ERROR:", err);
      return res.status(500).json({ message: "Server error", details: err.message });
    }
  }
);

// ?. Delete document
app.delete("/api/profile/documents/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    await db.query(
      "DELETE FROM user_documents WHERE id = ? AND user_id = ?",
      [id, req.user.id]
    );
    return res.json({ message: "Document deleted" });
  } catch (err) {
    console.error("DELETE DOCUMENT ERROR:", err);
    return res.status(500).json({ message: "Server error", details: err.message });
  }
});
const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
  console.log(`Server running on http://localhost:${PORT}`);
  await seedUniversities();
});
