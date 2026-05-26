import bcrypt from "bcrypt";

export function createAuthController({
  db,
  generateOtp,
  sendOtpEmail,
  sendResetEmail,
  signAuthToken,
  verifyGoogleIdToken,
}) {
  return {
    signup: async (req, res) => {
      try {
        const { full_name, email, password } = req.body;

        if (!full_name || !email || !password) {
          return res
            .status(400)
            .json({ message: "full_name, email, password are required" });
        }

        const [exists] = await db.query("SELECT id FROM users WHERE email = ?", [email]);
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
    },

    verifyOtp: async (req, res) => {
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

        if (!rows.length) {
          return res.status(400).json({ message: "Invalid or expired OTP" });
        }

        const record = rows[0];
        const [result] = await db.query(
          "INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)",
          [record.full_name, record.email, record.password_hash]
        );

        await db.query("DELETE FROM signup_otps WHERE email = ?", [email]);

        return res.json({
          message: "Email verified. You can now log in.",
          userId: result.insertId,
        });
      } catch (err) {
        console.error("VERIFY OTP ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    resendOtp: async (req, res) => {
      try {
        const { email } = req.body;
        if (!email) {
          return res.status(400).json({ message: "email is required" });
        }

        const [rows] = await db.query(
          "SELECT email FROM signup_otps WHERE email = ?",
          [email]
        );

        if (!rows.length) {
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
    },

    forgotPassword: async (req, res) => {
      try {
        const { email } = req.body;
        if (!email) {
          return res.status(400).json({ message: "email is required" });
        }

        const [users] = await db.query("SELECT id FROM users WHERE email = ?", [email]);
        if (!users.length) {
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
    },

    resetPassword: async (req, res) => {
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

        if (!rows.length) {
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
    },

    login: async (req, res) => {
      try {
        const { email, password } = req.body;

        if (!email || !password) {
          return res.status(400).json({ message: "email and password are required" });
        }

        const [rows] = await db.query(
          "SELECT id, full_name, email, password_hash, role, is_active FROM users WHERE email = ?",
          [email]
        );

        if (!rows.length) {
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
        if (!ok) {
          return res.status(401).json({ message: "Invalid credentials" });
        }

        if (!process.env.JWT_SECRET) {
          return res.status(500).json({
            message: "Server error",
            details: "JWT_SECRET missing in .env",
          });
        }

        await db.query("UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?", [user.id]);
        const token = signAuthToken(user);

        return res.json({
          message: "Login successful",
          token,
          user: { id: user.id, full_name: user.full_name, email: user.email, role: user.role },
        });
      } catch (err) {
        console.error("LOGIN ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    googleAuth: async (req, res) => {
      try {
        const { credential } = req.body;

        if (!credential) {
          return res.status(400).json({ message: "Google credential is required" });
        }

        if (!process.env.JWT_SECRET) {
          return res.status(500).json({
            message: "Server error",
            details: "JWT_SECRET missing in .env",
          });
        }

        const googleProfile = await verifyGoogleIdToken(credential);
        const email = String(googleProfile.email || "").trim().toLowerCase();
        const fullName = String(googleProfile.name || googleProfile.given_name || "Google User").trim();

        const [rows] = await db.query(
          "SELECT id, full_name, email, role, is_active FROM users WHERE email = ?",
          [email]
        );

        let user = rows[0];

        if (!user) {
          const [result] = await db.query(
            "INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)",
            [fullName, email, ""]
          );

          user = {
            id: result.insertId,
            full_name: fullName,
            email,
            role: "student",
            is_active: 1,
          };
        }

        if (!user.is_active) {
          return res.status(403).json({ message: "Account is inactive" });
        }

        await db.query("UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?", [user.id]);
        const token = signAuthToken(user);

        return res.json({
          message: "Google sign in successful",
          token,
          user: {
            id: user.id,
            full_name: user.full_name,
            email: user.email,
            role: user.role,
          },
        });
      } catch (err) {
        console.error("GOOGLE AUTH ERROR:", err);
        return res.status(500).json({
          message: "Google sign in failed",
          details: err.message,
        });
      }
    },
  };
}
