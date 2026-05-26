import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import crypto from "crypto";
import { db } from "./db.js";
import { createAuthGuards } from "./middleware/auth.js";
import { createEmailService, generateOtp } from "./services/emailService.js";
import { createScholarshipNotificationService } from "./services/scholarshipNotificationService.js";
import { createAuthController } from "./controllers/authController.js";
import { createExpenseController } from "./controllers/expenseController.js";
import { createCounselingController } from "./controllers/counselingController.js";
import { createAdminController } from "./controllers/adminController.js";
import { createProfileController } from "./controllers/profileController.js";
import { createDocumentController } from "./controllers/documentController.js";
import { createSettingsController } from "./controllers/settingsController.js";
import { createUniversityController } from "./controllers/universityController.js";
import { registerAuthRoutes } from "./routes/authRoutes.js";
import { registerExpenseRoutes } from "./routes/expenseRoutes.js";
import { registerCounselingRoutes } from "./routes/counselingRoutes.js";
import { registerAdminRoutes } from "./routes/adminRoutes.js";
import { registerProfileRoutes } from "./routes/profileRoutes.js";
import { registerDocumentRoutes } from "./routes/documentRoutes.js";
import { registerSettingsRoutes } from "./routes/settingsRoutes.js";
import { registerUniversityRoutes } from "./routes/universityRoutes.js";
import { toNumber } from "./utils/number.js";

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
const emailService = createEmailService();
const { sendOtpEmail, sendResetEmail, sendScholarshipAlertEmail } = emailService;

const {
  scholarshipTextChanged,
  notifyUsersAboutScholarshipUpdate,
} = createScholarshipNotificationService({ db, sendScholarshipAlertEmail });


const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const privateVaultRoot = path.join(__dirname, "private_uploads");
const documentVaultDir = path.join(privateVaultRoot, "document_vault");
if (!fs.existsSync(documentVaultDir)) {
  fs.mkdirSync(documentVaultDir, { recursive: true });
}

const ALLOWED_DOCUMENT_MIME_TYPES = new Set([
  "application/pdf",
  "image/jpeg",
  "image/png",
  "image/webp",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
]);

const MAX_DOCUMENT_SIZE_BYTES = 10 * 1024 * 1024;

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, documentVaultDir),
  filename: (req, file, cb) => {
    const extension = path.extname(file.originalname || "").replace(/[^a-zA-Z0-9.]/g, "").toLowerCase();
    const unique = `${Date.now()}-${crypto.randomBytes(12).toString("hex")}`;
    cb(null, `${unique}${extension}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_DOCUMENT_SIZE_BYTES },
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_DOCUMENT_MIME_TYPES.has(file.mimetype)) {
      return cb(new Error("Unsupported document type"));
    }
    return cb(null, true);
  },
});

app.use("/uploads", express.static(uploadsDir));

const formatFileSize = (bytes = 0) => `${(bytes / (1024 * 1024)).toFixed(2)} MB`;

const sanitizeDocumentType = (value = "", customValue = "") => {
  const normalized = String(value || "").trim().toLowerCase();
  const customNormalized = String(customValue || "")
    .replace(/[^a-zA-Z0-9\s().,&/-]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 60);

  const allowed = {
    passport: "Passport",
    transcript: "Transcript",
    certificate: "Certificate",
    school_leaving_certificate: "School Leaving Certificate",
    marksheet: "Marksheet",
    character_certificate: "Character Certificate",
    ielts: "IELTS",
    toefl: "TOEFL",
    sat: "SAT",
    financial: "Financial Document",
    visa: "Visa",
    resume: "Resume / CV",
    recommendation: "Recommendation Letter",
    sop: "Statement of Purpose",
    lor: "Letter of Recommendation",
    other: customNormalized || "Other",
    custom: customNormalized || "Other",
  };

  return allowed[normalized] || customNormalized || "Other";
};

const buildDocumentDownloadUrl = (documentId) => `/api/profile/documents/${documentId}/download`;

const signAuthToken = (user) =>
  jwt.sign(
    { id: user.id, email: user.email, full_name: user.full_name, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

const verifyGoogleIdToken = async (idToken) => {
  const response = await fetch(
    `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`
  );

  if (!response.ok) {
    throw new Error("Google token verification failed");
  }

  const payload = await response.json();

  if (!payload?.email || payload.email_verified !== "true") {
    throw new Error("Google account email is not verified");
  }

  const allowedClientId = process.env.GOOGLE_CLIENT_ID;
  if (allowedClientId && payload.aud !== allowedClientId) {
    throw new Error("Google client ID mismatch");
  }

  return payload;
};

const getDocumentVaultPinHash = async (userId) => {
  await ensureSettingsTable();
  const [[row]] = await db.query(
    `SELECT document_vault_pin_hash
     FROM user_settings
     WHERE user_id = ?`,
    [userId]
  );
  return row?.document_vault_pin_hash || null;
};

const verifyDocumentVaultPin = async (userId, pin) => {
  const storedHash = await getDocumentVaultPinHash(userId);
  if (!storedHash) return true;

  const normalizedPin = String(pin || "").trim();
  if (!normalizedPin) return false;

  return bcrypt.compare(normalizedPin, storedHash);
};

const requireDocumentVaultPin = async (req, res) => {
  if (req.user?.role === "admin" || req.user?.role === "agent") {
    return true;
  }

  const storedHash = await getDocumentVaultPinHash(req.user.id);
  if (!storedHash) {
    return true;
  }

  const pin = String(req.headers["x-vault-pin"] || "").trim();
  if (!pin) {
    res.status(423).json({ message: "Document vault PIN required." });
    return false;
  }

  const ok = await bcrypt.compare(pin, storedHash);
  if (!ok) {
    res.status(403).json({ message: "Invalid document vault PIN." });
    return false;
  }

  return true;
};

const documentVaultPinMiddleware = async (req, res, next) => {
  if (!(await requireDocumentVaultPin(req, res))) {
    return;
  }
  next();
};

const resolveDocumentAbsolutePath = (document) => {
  if (document?.stored_name) {
    return path.join(documentVaultDir, document.stored_name);
  }

  if (document?.file_url && document.file_url.startsWith("/uploads/")) {
    return path.join(uploadsDir, path.basename(document.file_url));
  }

  return "";
};

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
    await ensureUniversitiesTable();
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
      u.scholarship_name || null,
      u.scholarship_amount || null,
      u.scholarship_type || null,
      u.scholarship_eligibility_note || null,
      u.min_ielts_score || null,
      u.min_sat_score || null,
      u.admissions,
      u.location,
      u.contact,
      u.image_url,
    ]);

    await db.query(
      `INSERT INTO universities
        (name, country, city, ranking, website, overview, courses, fees, facilities, scholarships,
         scholarship_name, scholarship_amount, scholarship_type, scholarship_eligibility_note,
         min_ielts_score, min_sat_score, admissions, location, contact, image_url)
       VALUES ?`,
      [values]
    );
  } catch (err) {
    if (err?.errno === 1932 || String(err?.sqlMessage || "").includes("doesn't exist in engine")) {
      try {
        await db.query("DROP TABLE IF EXISTS universities");
        await ensureUniversitiesTable();

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
          u.scholarship_name || null,
          u.scholarship_amount || null,
          u.scholarship_type || null,
          u.scholarship_eligibility_note || null,
          u.min_ielts_score || null,
          u.min_sat_score || null,
          u.admissions,
          u.location,
          u.contact,
          u.image_url,
        ]);

        await db.query(
          `INSERT INTO universities
            (name, country, city, ranking, website, overview, courses, fees, facilities, scholarships,
             scholarship_name, scholarship_amount, scholarship_type, scholarship_eligibility_note,
             min_ielts_score, min_sat_score, admissions, location, contact, image_url)
           VALUES ?`,
          [values]
        );
        console.log(`Recreated and seeded ${seed.length} universities.`);
        return;
      } catch (recoveryErr) {
        console.error("UNIVERSITY SEED RECOVERY ERROR:", recoveryErr);
      }
    }
    console.error("UNIVERSITY SEED ERROR:", err);
  }
};

const ensureUniversitiesTable = async () => {
  try {
    await db.query(
      `CREATE TABLE IF NOT EXISTS universities (
        id INT NOT NULL AUTO_INCREMENT,
        name VARCHAR(200) NOT NULL,
        country VARCHAR(100) NOT NULL,
        city VARCHAR(100) NULL,
        ranking INT NULL,
        website VARCHAR(255) NULL,
        overview TEXT NULL,
        courses TEXT NULL,
        fees TEXT NULL,
        facilities TEXT NULL,
        scholarships TEXT NULL,
        scholarship_name VARCHAR(255) NULL,
        scholarship_amount DECIMAL(10,2) NULL,
        scholarship_type VARCHAR(40) NULL,
        scholarship_eligibility_note TEXT NULL,
        min_ielts_score DECIMAL(3,1) NULL,
        min_sat_score INT NULL,
        admissions TEXT NULL,
        location VARCHAR(150) NULL,
        contact VARCHAR(150) NULL,
        image_url VARCHAR(255) NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id)
      )`
    );
  } catch (err) {
    console.error("UNIVERSITIES TABLE ERROR:", err);
  }
};

const ensureSettingsTable = async () => {
  try {
    await db.query(
      `ALTER TABLE users
       ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP NULL DEFAULT NULL`
    );

    await db.query(
      `CREATE TABLE IF NOT EXISTS user_settings (
        user_id INT NOT NULL,
        email_notifications TINYINT(1) NOT NULL DEFAULT 1,
        scholarship_alerts TINYINT(1) NOT NULL DEFAULT 1,
        marketing_updates TINYINT(1) NOT NULL DEFAULT 0,
        preferred_currency VARCHAR(10) NOT NULL DEFAULT 'USD',
        counseling_reply_alerts TINYINT(1) NOT NULL DEFAULT 1,
        document_review_alerts TINYINT(1) NOT NULL DEFAULT 1,
        expense_reminder_alerts TINYINT(1) NOT NULL DEFAULT 0,
        show_profile_to_agent TINYINT(1) NOT NULL DEFAULT 1,
        allow_agent_email_contact TINYINT(1) NOT NULL DEFAULT 1,
        allow_profile_matching TINYINT(1) NOT NULL DEFAULT 1,
        preferred_country_default VARCHAR(100) NULL,
        default_language VARCHAR(40) NOT NULL DEFAULT 'English',
        default_intake_session VARCHAR(60) NULL,
        monthly_budget_target DECIMAL(10,2) NULL,
        include_part_time_income TINYINT(1) NOT NULL DEFAULT 1,
        expense_reminder_day INT NULL,
        allowed_document_reminder TINYINT(1) NOT NULL DEFAULT 0,
        auto_lock_vault_on_logout TINYINT(1) NOT NULL DEFAULT 1,
        document_upload_reminder TINYINT(1) NOT NULL DEFAULT 0,
        phone_number VARCHAR(40) NULL,
        emergency_contact VARCHAR(120) NULL,
        profile_photo_url VARCHAR(255) NULL,
        document_vault_pin_hash VARCHAR(255) NULL,
        document_vault_pin_updated_at TIMESTAMP NULL DEFAULT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id),
        CONSTRAINT fk_user_settings_user
          FOREIGN KEY (user_id)
          REFERENCES users(id)
          ON DELETE CASCADE
      )`
    );

    await db.query(
      `ALTER TABLE user_settings
       ADD COLUMN IF NOT EXISTS counseling_reply_alerts TINYINT(1) NOT NULL DEFAULT 1,
       ADD COLUMN IF NOT EXISTS document_review_alerts TINYINT(1) NOT NULL DEFAULT 1,
       ADD COLUMN IF NOT EXISTS expense_reminder_alerts TINYINT(1) NOT NULL DEFAULT 0,
       ADD COLUMN IF NOT EXISTS show_profile_to_agent TINYINT(1) NOT NULL DEFAULT 1,
       ADD COLUMN IF NOT EXISTS allow_agent_email_contact TINYINT(1) NOT NULL DEFAULT 1,
       ADD COLUMN IF NOT EXISTS allow_profile_matching TINYINT(1) NOT NULL DEFAULT 1,
       ADD COLUMN IF NOT EXISTS preferred_country_default VARCHAR(100) NULL,
       ADD COLUMN IF NOT EXISTS default_language VARCHAR(40) NOT NULL DEFAULT 'English',
       ADD COLUMN IF NOT EXISTS default_intake_session VARCHAR(60) NULL,
       ADD COLUMN IF NOT EXISTS monthly_budget_target DECIMAL(10,2) NULL,
       ADD COLUMN IF NOT EXISTS include_part_time_income TINYINT(1) NOT NULL DEFAULT 1,
       ADD COLUMN IF NOT EXISTS expense_reminder_day INT NULL,
       ADD COLUMN IF NOT EXISTS allowed_document_reminder TINYINT(1) NOT NULL DEFAULT 0,
       ADD COLUMN IF NOT EXISTS auto_lock_vault_on_logout TINYINT(1) NOT NULL DEFAULT 1,
       ADD COLUMN IF NOT EXISTS document_upload_reminder TINYINT(1) NOT NULL DEFAULT 0,
       ADD COLUMN IF NOT EXISTS phone_number VARCHAR(40) NULL,
       ADD COLUMN IF NOT EXISTS emergency_contact VARCHAR(120) NULL,
       ADD COLUMN IF NOT EXISTS profile_photo_url VARCHAR(255) NULL,
       ADD COLUMN IF NOT EXISTS document_vault_pin_hash VARCHAR(255) NULL,
       ADD COLUMN IF NOT EXISTS document_vault_pin_updated_at TIMESTAMP NULL DEFAULT NULL`
    );
  } catch (err) {
    console.error("SETTINGS TABLE ERROR:", err);
  }
};

const ensureScholarshipCriteriaColumns = async () => {
  try {
    await db.query(
      `ALTER TABLE universities
       ADD COLUMN IF NOT EXISTS min_ielts_score DECIMAL(3,1) NULL,
       ADD COLUMN IF NOT EXISTS min_sat_score INT NULL,
       ADD COLUMN IF NOT EXISTS scholarship_name VARCHAR(255) NULL,
       ADD COLUMN IF NOT EXISTS scholarship_amount DECIMAL(10,2) NULL,
       ADD COLUMN IF NOT EXISTS scholarship_type VARCHAR(40) NULL,
       ADD COLUMN IF NOT EXISTS scholarship_eligibility_note TEXT NULL`
    );

    await db.query(
      `ALTER TABLE user_academics
       ADD COLUMN IF NOT EXISTS sat_score VARCHAR(20) NULL`
    );
  } catch (err) {
    console.error("SCHOLARSHIP CRITERIA COLUMN ERROR:", err);
  }
};

const ensureExpensePlansTable = async () => {
  try {
    await db.query(
      `CREATE TABLE IF NOT EXISTS expense_plans (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        university_id INT NOT NULL,
        applied TINYINT(1) NOT NULL DEFAULT 0,
        planner_stage VARCHAR(20) NOT NULL DEFAULT 'before-applying',
        has_arrived TINYINT(1) NULL,
        works_part_time TINYINT(1) NULL,
        weekly_income DECIMAL(10,2) NULL,
        application_fee DECIMAL(10,2) NULL,
        transcript_fee DECIMAL(10,2) NULL,
        english_test_fee DECIMAL(10,2) NULL,
        visa_fee DECIMAL(10,2) NULL,
        courier_fee DECIMAL(10,2) NULL,
        deposit_fee DECIMAL(10,2) NULL,
        semester_fee DECIMAL(10,2) NULL,
        monthly_rent DECIMAL(10,2) NULL,
        monthly_insurance DECIMAL(10,2) NULL,
        monthly_food DECIMAL(10,2) NULL,
        monthly_transport DECIMAL(10,2) NULL,
        monthly_utilities DECIMAL(10,2) NULL,
        other_fee DECIMAL(10,2) NULL,
        other_note TEXT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_expense_plan_user_university (user_id, university_id),
        CONSTRAINT fk_expense_plans_user
          FOREIGN KEY (user_id)
          REFERENCES users(id)
          ON DELETE CASCADE,
        CONSTRAINT fk_expense_plans_university
          FOREIGN KEY (university_id)
          REFERENCES universities(id)
          ON DELETE CASCADE
      )`
    );

    await db.query(
      `ALTER TABLE expense_plans
       ADD COLUMN IF NOT EXISTS planner_stage VARCHAR(20) NOT NULL DEFAULT 'before-applying',
       ADD COLUMN IF NOT EXISTS has_arrived TINYINT(1) NULL,
       ADD COLUMN IF NOT EXISTS works_part_time TINYINT(1) NULL,
       ADD COLUMN IF NOT EXISTS weekly_income DECIMAL(10,2) NULL`
    );

    await db.query(
      `ALTER TABLE expense_plans
       MODIFY COLUMN planner_stage VARCHAR(20) NOT NULL DEFAULT 'before-applying'`
    );
  } catch (err) {
    console.error("EXPENSE PLANS TABLE ERROR:", err);
  }
};

const ensureExpenseEntriesTable = async () => {
  try {
    await db.query(
      `CREATE TABLE IF NOT EXISTS expense_entries (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        university_id INT NOT NULL,
        entry_type VARCHAR(20) NOT NULL DEFAULT 'expense',
        category VARCHAR(60) NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        month VARCHAR(7) NOT NULL,
        note TEXT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        CONSTRAINT fk_expense_entries_user
          FOREIGN KEY (user_id)
          REFERENCES users(id)
          ON DELETE CASCADE,
        CONSTRAINT fk_expense_entries_university
          FOREIGN KEY (university_id)
          REFERENCES universities(id)
          ON DELETE CASCADE
      )`
    );

    await db.query(
      `ALTER TABLE expense_entries
       ADD COLUMN IF NOT EXISTS entry_type VARCHAR(20) NOT NULL DEFAULT 'expense'`
    );
  } catch (err) {
    console.error("EXPENSE ENTRIES TABLE ERROR:", err);
  }
};

const ensureDocumentReviewColumns = async () => {
  try {
    await db.query(
      `ALTER TABLE user_documents
       ADD COLUMN IF NOT EXISTS review_status VARCHAR(20) NOT NULL DEFAULT 'pending',
       ADD COLUMN IF NOT EXISTS review_comment TEXT NULL,
       ADD COLUMN IF NOT EXISTS reviewed_by INT NULL,
       ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMP NULL DEFAULT NULL`
    );
  } catch (err) {
    console.error("DOCUMENT REVIEW COLUMN ERROR:", err);
  }
};

const ensureDocumentVaultColumns = async () => {
  try {
    await db.query(
      `ALTER TABLE user_documents
       ADD COLUMN IF NOT EXISTS stored_name VARCHAR(255) NULL,
       ADD COLUMN IF NOT EXISTS file_size_bytes BIGINT NULL,
       ADD COLUMN IF NOT EXISTS file_hash VARCHAR(128) NULL,
       ADD COLUMN IF NOT EXISTS document_type VARCHAR(60) NOT NULL DEFAULT 'other',
       ADD COLUMN IF NOT EXISTS storage_scope VARCHAR(30) NOT NULL DEFAULT 'vault'`
    );
  } catch (err) {
    console.error("DOCUMENT VAULT COLUMN ERROR:", err);
  }
};

const ensureApplicationsTable = async () => {
  try {
    const [existingTables] = await db.query("SHOW TABLES LIKE 'applications'");
    if (existingTables.length > 0) {
      const [columns] = await db.query("SHOW COLUMNS FROM applications");
      const columnNames = new Set(columns.map((column) => column.Field));

      if (!columnNames.has("university_id")) {
        const [[countRow]] = await db.query("SELECT COUNT(*) AS count FROM applications");
        if ((countRow?.count || 0) === 0) {
          await db.query("DROP TABLE applications");
        } else {
          throw new Error("Legacy applications table detected with existing rows. Manual migration is required.");
        }
      }
    }

    await db.query(
      `CREATE TABLE IF NOT EXISTS applications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        university_id INT NOT NULL,
        status VARCHAR(40) NOT NULL DEFAULT 'applying',
        source VARCHAR(40) NOT NULL DEFAULT 'student_portal',
        notes TEXT NULL,
        submitted_at TIMESTAMP NULL DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_application_user_university (user_id, university_id),
        CONSTRAINT fk_applications_user
          FOREIGN KEY (user_id)
          REFERENCES users(id)
          ON DELETE CASCADE,
        CONSTRAINT fk_applications_university
          FOREIGN KEY (university_id)
          REFERENCES universities(id)
          ON DELETE CASCADE
      )`
    );

    await db.query(
      `ALTER TABLE applications
       MODIFY COLUMN status VARCHAR(40) NOT NULL DEFAULT 'applying'`
    );
  } catch (err) {
    console.error("APPLICATIONS TABLE ERROR:", err);
  }
};

const ensureCounselingRequestsTable = async () => {
  try {
    await db.query(
      `CREATE TABLE IF NOT EXISTS counseling_requests (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        topic VARCHAR(180) NOT NULL,
        message TEXT NOT NULL,
        preferred_country VARCHAR(100) NULL,
        priority VARCHAR(30) NOT NULL DEFAULT 'normal',
        status VARCHAR(30) NOT NULL DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        CONSTRAINT fk_counseling_requests_user
          FOREIGN KEY (user_id)
          REFERENCES users(id)
          ON DELETE CASCADE
      )`
    );
  } catch (err) {
    console.error("COUNSELING REQUESTS TABLE ERROR:", err);
  }
};

const ensureUniversityAuditLogsTable = async () => {
  try {
    await db.query(
      `CREATE TABLE IF NOT EXISTS university_audit_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        university_id INT NOT NULL,
        action VARCHAR(20) NOT NULL,
        editor_user_id INT NOT NULL,
        editor_role VARCHAR(30) NULL,
        changed_fields TEXT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_university_audit_logs_university
          FOREIGN KEY (university_id)
          REFERENCES universities(id)
          ON DELETE CASCADE,
        CONSTRAINT fk_university_audit_logs_user
          FOREIGN KEY (editor_user_id)
          REFERENCES users(id)
          ON DELETE CASCADE
      )`
    );
  } catch (err) {
    console.error("UNIVERSITY AUDIT TABLE ERROR:", err);
  }
};

const logUniversityAudit = async ({
  universityId,
  action,
  editorUserId,
  editorRole,
  changedFields = [],
}) => {
  try {
    await db.query(
      `INSERT INTO university_audit_logs
        (university_id, action, editor_user_id, editor_role, changed_fields)
       VALUES (?, ?, ?, ?, ?)`,
      [
        universityId,
        action,
        editorUserId,
        editorRole || null,
        changedFields.length ? JSON.stringify(changedFields) : null,
      ]
    );
  } catch (err) {
    console.error("UNIVERSITY AUDIT INSERT ERROR:", err);
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
const { authMiddleware, requireAdmin, requireAgentOrAdmin } = createAuthGuards(db);
const authController = createAuthController({
  db,
  generateOtp,
  sendOtpEmail,
  sendResetEmail,
  signAuthToken,
  verifyGoogleIdToken,
});
const adminController = createAdminController({ db, buildDocumentDownloadUrl });
const profileController = createProfileController({ db });
const documentController = createDocumentController({
  db,
  bcrypt,
  fs,
  crypto,
  ensureSettingsTable,
  getDocumentVaultPinHash,
  verifyDocumentVaultPin,
  requireDocumentVaultPin,
  resolveDocumentAbsolutePath,
  sanitizeDocumentType,
  formatFileSize,
  buildDocumentDownloadUrl,
});
const settingsController = createSettingsController({
  db,
  ensureSettingsTable,
  signAuthToken,
});
const universityController = createUniversityController({
  db,
  toNumber,
  scholarshipTextChanged,
  notifyUsersAboutScholarshipUpdate,
  logUniversityAudit,
});
registerAuthRoutes(app, authController);
registerAdminRoutes(app, {
  authMiddleware,
  requireAdmin,
  requireAgentOrAdmin,
  controller: adminController,
});
registerProfileRoutes(app, {
  authMiddleware,
  controller: profileController,
});
registerDocumentRoutes(app, {
  authMiddleware,
  documentVaultPinMiddleware,
  upload,
  controller: documentController,
});
registerSettingsRoutes(app, {
  authMiddleware,
  controller: settingsController,
});
registerUniversityRoutes(app, {
  authMiddleware,
  requireAdmin,
  requireAgentOrAdmin,
  controller: universityController,
});
const expenseController = createExpenseController({ db });
registerExpenseRoutes(app, { authMiddleware, controller: expenseController });
const counselingController = createCounselingController({ db });
registerCounselingRoutes(app, {
  authMiddleware,
  requireAgentOrAdmin,
  controller: counselingController,
});
app.use((err, req, res, next) => {
  if (!err) return next();

  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({ message: "Each file must be 10 MB or smaller." });
    }
    return res.status(400).json({ message: err.message || "Document upload failed." });
  }

  if (err.message === "Unsupported document type") {
    return res.status(400).json({ message: "Only PDF, JPG, PNG, WEBP, DOC, and DOCX files are allowed." });
  }

  return next(err);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
  console.log(`Server running on http://localhost:${PORT}`);
  await ensureUniversitiesTable();
  await ensureSettingsTable();
  await ensureScholarshipCriteriaColumns();
  await ensureExpensePlansTable();
  await ensureExpenseEntriesTable();
  await ensureDocumentReviewColumns();
  await ensureDocumentVaultColumns();
  await ensureApplicationsTable();
  await ensureCounselingRequestsTable();
  await ensureUniversityAuditLogsTable();
  await seedUniversities();
});


