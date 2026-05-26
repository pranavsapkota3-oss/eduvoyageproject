export function createProfileController({ db }) {
  return {
    getProfile: async (req, res) => {
      return res.json({
        message: "Profile fetched",
        user: req.user,
      });
    },

    getPersonal: async (req, res) => {
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
    },

    updatePersonal: async (req, res) => {
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
    },

    getAcademic: async (req, res) => {
      try {
        const [rows] = await db.query(
          `SELECT highest_level, gpa, school_name, graduation_year, field_of_study,
                  ielts_score, toefl_score, gre_score, gmat_score, sat_score
           FROM user_academics
           WHERE user_id = ?`,
          [req.user.id]
        );

        return res.json({ academic: rows[0] || null });
      } catch (err) {
        console.error("GET ACADEMIC PROFILE ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    updateAcademic: async (req, res) => {
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
          sat_score,
        } = req.body;

        await db.query(
          `INSERT INTO user_academics
            (user_id, highest_level, gpa, school_name, graduation_year, field_of_study,
             ielts_score, toefl_score, gre_score, gmat_score, sat_score)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON DUPLICATE KEY UPDATE
             highest_level = VALUES(highest_level),
             gpa = VALUES(gpa),
             school_name = VALUES(school_name),
             graduation_year = VALUES(graduation_year),
             field_of_study = VALUES(field_of_study),
             ielts_score = VALUES(ielts_score),
             toefl_score = VALUES(toefl_score),
             gre_score = VALUES(gre_score),
             gmat_score = VALUES(gmat_score),
             sat_score = VALUES(sat_score)`,
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
            sat_score || null,
          ]
        );

        return res.json({ message: "Academic background updated" });
      } catch (err) {
        console.error("UPDATE ACADEMIC PROFILE ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    getPreferences: async (req, res) => {
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
    },

    updatePreferences: async (req, res) => {
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
    },

    listApplications: async (req, res) => {
      try {
        const [rows] = await db.query(
          `SELECT a.id, a.user_id, a.university_id, a.status, a.source, a.notes, a.submitted_at, a.created_at, a.updated_at,
                  un.name AS university_name, un.country AS university_country, un.city AS university_city
           FROM applications a
           JOIN universities un ON un.id = a.university_id
           WHERE a.user_id = ?
           ORDER BY a.updated_at DESC`,
          [req.user.id]
        );

        return res.json({ applications: rows });
      } catch (err) {
        console.error("GET PROFILE APPLICATIONS ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    createApplication: async (req, res) => {
      try {
        const universityId = Number(req.body.university_id);
        const notes = String(req.body.notes || "").trim();
        const source = String(req.body.source || "student_portal").trim();
        const requestedStatus = String(req.body.status || "applying").trim().toLowerCase();
        const allowedStatuses = ["shortlisted", "applying", "submitted", "offer received", "accepted", "rejected", "stopped applying"];

        if (!Number.isInteger(universityId) || universityId <= 0) {
          return res.status(400).json({ message: "Valid university_id is required" });
        }

        if (!allowedStatuses.includes(requestedStatus)) {
          return res.status(400).json({ message: "Valid application status is required" });
        }

        await db.query(
          `INSERT INTO applications (user_id, university_id, status, source, notes)
           VALUES (?, ?, ?, ?, ?)
           ON DUPLICATE KEY UPDATE
             status = CASE
               WHEN status IN ('accepted', 'rejected', 'offer received', 'stopped applying') THEN status
               WHEN status = 'submitted' AND VALUES(status) IN ('shortlisted', 'applying') THEN status
               ELSE VALUES(status)
             END,
             source = VALUES(source),
             notes = COALESCE(NULLIF(VALUES(notes), ''), notes)`,
          [req.user.id, universityId, requestedStatus, source || "student_portal", notes || null]
        );

        const [[application]] = await db.query(
          `SELECT a.id, a.user_id, a.university_id, a.status, a.source, a.notes, a.submitted_at, a.created_at, a.updated_at,
                  un.name AS university_name, un.country AS university_country, un.city AS university_city
           FROM applications a
           JOIN universities un ON un.id = a.university_id
           WHERE a.user_id = ? AND a.university_id = ?`,
          [req.user.id, universityId]
        );

        return res.status(201).json({ message: "Application created", application });
      } catch (err) {
        console.error("CREATE APPLICATION ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    updateApplicationStatus: async (req, res) => {
      try {
        const applicationId = Number(req.params.id);
        const nextStatus = String(req.body.status || "").trim().toLowerCase();
        const allowedStatuses = ["shortlisted", "applying", "submitted", "offer received", "accepted", "rejected", "stopped applying"];
  const allowedTransitions = {
    shortlisted: ["applying", "stopped applying"],
    applying: ["submitted", "stopped applying"],
    submitted: ["offer received", "accepted", "rejected", "stopped applying"],
    "offer received": ["accepted", "rejected", "stopped applying"],
    accepted: [],
    rejected: [],
    "stopped applying": [],
  };

        if (!Number.isInteger(applicationId) || applicationId <= 0) {
          return res.status(400).json({ message: "Valid application id is required" });
        }

        if (!allowedStatuses.includes(nextStatus)) {
          return res.status(400).json({ message: "Valid application status is required" });
        }

        const [[existing]] = await db.query(
          `SELECT id, user_id, status
           FROM applications
           WHERE id = ? AND user_id = ?`,
          [applicationId, req.user.id]
        );

        if (!existing) {
          return res.status(404).json({ message: "Application not found" });
        }

        const currentStatus = existing.status || "shortlisted";
        const nextAllowed = allowedTransitions[currentStatus] || [];

        if (!nextAllowed.includes(nextStatus)) {
          return res.status(400).json({ message: "This application cannot move to that status from the current step." });
        }

        await db.query(
          `UPDATE applications
           SET status = ?, submitted_at = CASE WHEN ? = 'submitted' AND submitted_at IS NULL THEN CURRENT_TIMESTAMP ELSE submitted_at END
           WHERE id = ? AND user_id = ?`,
          [nextStatus, nextStatus, applicationId, req.user.id]
        );

        const [[application]] = await db.query(
          `SELECT a.id, a.user_id, a.university_id, a.status, a.source, a.notes, a.submitted_at, a.created_at, a.updated_at,
                  un.name AS university_name, un.country AS university_country, un.city AS university_city
           FROM applications a
           JOIN universities un ON un.id = a.university_id
           WHERE a.id = ? AND a.user_id = ?`,
          [applicationId, req.user.id]
        );

        return res.json({ message: "Application moved to the next step.", application });
      } catch (err) {
        console.error("UPDATE PROFILE APPLICATION STATUS ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },
  };
}
