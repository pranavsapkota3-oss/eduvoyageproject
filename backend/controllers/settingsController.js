import bcrypt from "bcrypt";

export function createSettingsController({
  db,
  ensureSettingsTable,
  signAuthToken,
}) {
  return {
    getSettings: async (req, res) => {
      try {
        const [[userRow]] = await db.query(
          `SELECT id, full_name, email, role, last_login_at
           FROM users
           WHERE id = ?`,
          [req.user.id]
        );

        if (!userRow) {
          return res.status(404).json({ message: "User not found" });
        }

        let settingRows = [];
        try {
          const [rows] = await db.query(
            `SELECT email_notifications, scholarship_alerts, marketing_updates, preferred_currency,
                    counseling_reply_alerts, document_review_alerts, expense_reminder_alerts,
                    show_profile_to_agent, allow_agent_email_contact, allow_profile_matching,
                    preferred_country_default, default_language, default_intake_session,
                    monthly_budget_target, include_part_time_income, expense_reminder_day,
                    allowed_document_reminder, auto_lock_vault_on_logout, document_upload_reminder,
                    phone_number, emergency_contact, profile_photo_url
             FROM user_settings
             WHERE user_id = ?`,
            [req.user.id]
          );
          settingRows = rows;
        } catch (settingsErr) {
          if (settingsErr.code === "ER_NO_SUCH_TABLE") {
            await ensureSettingsTable();
          } else {
            throw settingsErr;
          }
        }

        const settings = settingRows[0] || {
          email_notifications: 1,
          scholarship_alerts: 1,
          marketing_updates: 0,
          preferred_currency: "USD",
          counseling_reply_alerts: 1,
          document_review_alerts: 1,
          expense_reminder_alerts: 0,
          show_profile_to_agent: 1,
          allow_agent_email_contact: 1,
          allow_profile_matching: 1,
          preferred_country_default: "",
          default_language: "English",
          default_intake_session: "",
          monthly_budget_target: null,
          include_part_time_income: 1,
          expense_reminder_day: null,
          allowed_document_reminder: 0,
          auto_lock_vault_on_logout: 1,
          document_upload_reminder: 0,
          phone_number: "",
          emergency_contact: "",
          profile_photo_url: "",
        };

        return res.json({
          profile: {
            full_name: userRow.full_name || "",
            email: userRow.email || "",
            role: userRow.role || "student",
            phone_number: settings.phone_number || "",
            emergency_contact: settings.emergency_contact || "",
            profile_photo_url: settings.profile_photo_url || "",
          },
          security: {
            last_login_at: userRow.last_login_at || null,
          },
          preferences: {
            email_notifications: !!settings.email_notifications,
            scholarship_alerts: !!settings.scholarship_alerts,
            marketing_updates: !!settings.marketing_updates,
            preferred_currency: settings.preferred_currency || "USD",
            counseling_reply_alerts: !!settings.counseling_reply_alerts,
            document_review_alerts: !!settings.document_review_alerts,
            expense_reminder_alerts: !!settings.expense_reminder_alerts,
            show_profile_to_agent: !!settings.show_profile_to_agent,
            allow_agent_email_contact: !!settings.allow_agent_email_contact,
            allow_profile_matching: !!settings.allow_profile_matching,
            preferred_country_default: settings.preferred_country_default || "",
            default_language: settings.default_language || "English",
            default_intake_session: settings.default_intake_session || "",
            monthly_budget_target: settings.monthly_budget_target ?? "",
            include_part_time_income: !!settings.include_part_time_income,
            expense_reminder_day: settings.expense_reminder_day ?? "",
            allowed_document_reminder: !!settings.allowed_document_reminder,
            auto_lock_vault_on_logout: !!settings.auto_lock_vault_on_logout,
            document_upload_reminder: !!settings.document_upload_reminder,
          },
        });
      } catch (err) {
        console.error("GET SETTINGS ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    updateProfile: async (req, res) => {
      try {
        const {
          full_name,
          email,
          phone_number = "",
          emergency_contact = "",
          profile_photo_url = "",
        } = req.body;
        if (!full_name || !email) {
          return res.status(400).json({ message: "full_name and email are required" });
        }

        const normalizedEmail = String(email).trim().toLowerCase();
        const normalizedName = String(full_name).trim();

        const [exists] = await db.query(
          "SELECT id FROM users WHERE email = ? AND id <> ?",
          [normalizedEmail, req.user.id]
        );
        if (exists.length > 0) {
          return res.status(409).json({ message: "Email already in use" });
        }

        await db.query(
          "UPDATE users SET full_name = ?, email = ? WHERE id = ?",
          [normalizedName, normalizedEmail, req.user.id]
        );

        await ensureSettingsTable();
        await db.query(
          `INSERT INTO user_settings
            (user_id, phone_number, emergency_contact, profile_photo_url)
           VALUES (?, ?, ?, ?)
           ON DUPLICATE KEY UPDATE
             phone_number = VALUES(phone_number),
             emergency_contact = VALUES(emergency_contact),
             profile_photo_url = VALUES(profile_photo_url)`,
          [
            req.user.id,
            String(phone_number || "").trim() || null,
            String(emergency_contact || "").trim() || null,
            String(profile_photo_url || "").trim() || null,
          ]
        );

        const [rows] = await db.query(
          "SELECT id, full_name, email, role FROM users WHERE id = ?",
          [req.user.id]
        );
        const user = rows[0];
        const token = signAuthToken(user);

        return res.json({
          message: "Profile settings updated",
          token,
          user: {
            id: user.id,
            full_name: user.full_name,
            email: user.email,
            role: user.role,
            avatar: String(profile_photo_url || "").trim() || null,
          },
        });
      } catch (err) {
        console.error("UPDATE SETTINGS PROFILE ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    updatePassword: async (req, res) => {
      try {
        const { current_password, new_password } = req.body;

        if (!current_password || !new_password) {
          return res.status(400).json({ message: "current_password and new_password are required" });
        }
        if (String(new_password).length < 6) {
          return res.status(400).json({ message: "New password must be at least 6 characters" });
        }

        const [rows] = await db.query(
          "SELECT password_hash FROM users WHERE id = ?",
          [req.user.id]
        );
        if (!rows.length) {
          return res.status(404).json({ message: "User not found" });
        }

        const ok = await bcrypt.compare(current_password, rows[0].password_hash || "");
        if (!ok) {
          return res.status(401).json({ message: "Current password is incorrect" });
        }

        const password_hash = await bcrypt.hash(new_password, 10);
        await db.query("UPDATE users SET password_hash = ? WHERE id = ?", [password_hash, req.user.id]);

        return res.json({ message: "Password updated successfully" });
      } catch (err) {
        console.error("UPDATE SETTINGS PASSWORD ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    updatePreferences: async (req, res) => {
      try {
        const {
          email_notifications = true,
          scholarship_alerts = true,
          marketing_updates = false,
          preferred_currency = "USD",
          counseling_reply_alerts = true,
          document_review_alerts = true,
          expense_reminder_alerts = false,
          show_profile_to_agent = true,
          allow_agent_email_contact = true,
          allow_profile_matching = true,
          preferred_country_default = "",
          default_language = "English",
          default_intake_session = "",
          monthly_budget_target = null,
          include_part_time_income = true,
          expense_reminder_day = null,
          allowed_document_reminder = false,
          auto_lock_vault_on_logout = true,
          document_upload_reminder = false,
        } = req.body;

        const allowedCurrencies = ["USD", "CAD", "AUD", "GBP", "NPR"];
        const safeCurrency = allowedCurrencies.includes(String(preferred_currency).toUpperCase())
          ? String(preferred_currency).toUpperCase()
          : "USD";
        const reminderDay = Number(expense_reminder_day);
        const safeReminderDay = Number.isInteger(reminderDay) && reminderDay >= 1 && reminderDay <= 31
          ? reminderDay
          : null;

        await ensureSettingsTable();
        await db.query(
          `INSERT INTO user_settings
              (user_id, email_notifications, scholarship_alerts, marketing_updates, preferred_currency,
               counseling_reply_alerts, document_review_alerts, expense_reminder_alerts,
               show_profile_to_agent, allow_agent_email_contact, allow_profile_matching,
               preferred_country_default, default_language, default_intake_session,
               monthly_budget_target, include_part_time_income, expense_reminder_day,
               allowed_document_reminder, auto_lock_vault_on_logout, document_upload_reminder)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
              email_notifications = VALUES(email_notifications),
              scholarship_alerts = VALUES(scholarship_alerts),
              marketing_updates = VALUES(marketing_updates),
              preferred_currency = VALUES(preferred_currency),
              counseling_reply_alerts = VALUES(counseling_reply_alerts),
              document_review_alerts = VALUES(document_review_alerts),
              expense_reminder_alerts = VALUES(expense_reminder_alerts),
              show_profile_to_agent = VALUES(show_profile_to_agent),
              allow_agent_email_contact = VALUES(allow_agent_email_contact),
              allow_profile_matching = VALUES(allow_profile_matching),
              preferred_country_default = VALUES(preferred_country_default),
              default_language = VALUES(default_language),
              default_intake_session = VALUES(default_intake_session),
              monthly_budget_target = VALUES(monthly_budget_target),
              include_part_time_income = VALUES(include_part_time_income),
              expense_reminder_day = VALUES(expense_reminder_day),
              allowed_document_reminder = VALUES(allowed_document_reminder),
              auto_lock_vault_on_logout = VALUES(auto_lock_vault_on_logout),
              document_upload_reminder = VALUES(document_upload_reminder)`,
          [
            req.user.id,
            email_notifications ? 1 : 0,
            scholarship_alerts ? 1 : 0,
            marketing_updates ? 1 : 0,
            safeCurrency,
            counseling_reply_alerts ? 1 : 0,
            document_review_alerts ? 1 : 0,
            expense_reminder_alerts ? 1 : 0,
            show_profile_to_agent ? 1 : 0,
            allow_agent_email_contact ? 1 : 0,
            allow_profile_matching ? 1 : 0,
            String(preferred_country_default || "").trim() || null,
            String(default_language || "English").trim() || "English",
            String(default_intake_session || "").trim() || null,
            monthly_budget_target === "" ? null : Number(monthly_budget_target) || null,
            include_part_time_income ? 1 : 0,
            safeReminderDay,
            allowed_document_reminder ? 1 : 0,
            auto_lock_vault_on_logout ? 1 : 0,
            document_upload_reminder ? 1 : 0,
          ]
        );

        return res.json({ message: "Preferences updated" });
      } catch (err) {
        console.error("UPDATE SETTINGS PREFERENCES ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    logoutAllDevices: async (req, res) => {
      try {
        try {
          await db.query("DELETE FROM refresh_tokens WHERE user_id = ?", [req.user.id]);
        } catch (tokenErr) {
          if (tokenErr.code !== "ER_NO_SUCH_TABLE") {
            throw tokenErr;
          }
        }

        return res.json({ message: "Logged out from all saved device sessions." });
      } catch (err) {
        console.error("LOGOUT ALL DEVICES ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    deactivateAccount: async (req, res) => {
      try {
        await db.query("UPDATE users SET is_active = 0 WHERE id = ?", [req.user.id]);
        return res.json({ message: "Account deactivated successfully." });
      } catch (err) {
        console.error("DEACTIVATE ACCOUNT ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },
  };
}
