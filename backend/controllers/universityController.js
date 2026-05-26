export function createUniversityController({
  db,
  toNumber,
  scholarshipTextChanged,
  notifyUsersAboutScholarshipUpdate,
  logUniversityAudit,
}) {
  const firstCountry = (preferredCountries) => {
    if (!preferredCountries) return null;
    const parts = String(preferredCountries)
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
    return parts.length ? parts[0] : null;
  };

  const scholarshipTier = (score) => {
    if (score >= 85) return { title: "High Merit Scholarship", coverage: "40% - 70% tuition waiver" };
    if (score >= 65) return { title: "Merit Scholarship", coverage: "20% - 40% tuition waiver" };
    if (score >= 45) return { title: "Admission Scholarship", coverage: "10% - 25% tuition support" };
    return { title: "Application Grant", coverage: "Up to 10% tuition support" };
  };

  const formatScholarshipCoverage = (amount, type) => {
    const numericAmount = toNumber(amount);
    const normalizedType = String(type || "").trim().toLowerCase();

    if (normalizedType === "full_tuition") {
      return "Full tuition";
    }

    if (numericAmount === null) {
      return null;
    }

    if (normalizedType === "percentage_waiver") {
      return `${numericAmount}% tuition waiver`;
    }

    return `USD ${numericAmount.toLocaleString()} fixed award`;
  };

  const parseFeeAmount = (feeText) => {
    if (!feeText) return null;
    const normalized = String(feeText).replace(/,/g, "");
    const matches = normalized.match(/\d{4,6}(\.\d+)?/g);
    if (!matches?.length) return null;
    const largest = matches
      .map((value) => Number(value))
      .filter((value) => Number.isFinite(value))
      .sort((a, b) => b - a)[0];
    return largest || null;
  };

  return {
    listUniversities: async (req, res) => {
      try {
        const page = Math.max(1, Number(req.query.page || 1));
        const limit = Math.max(1, Math.min(200, Number(req.query.limit || 10)));
        const offset = (page - 1) * limit;
        const q = String(req.query.q || "").trim();
        const country = String(req.query.country || "").trim();

        const filters = [];
        const params = [];
        if (country) {
          filters.push("LOWER(country) LIKE LOWER(?)");
          params.push(`%${country}%`);
        }
        if (q) {
          filters.push("(name LIKE ? OR country LIKE ? OR city LIKE ?)");
          params.push(`%${q}%`, `%${q}%`, `%${q}%`);
        }
        const whereClause = filters.length ? `WHERE ${filters.join(" AND ")}` : "";

        const [[countRow]] = await db.query(
          `SELECT COUNT(*) AS total FROM universities ${whereClause}`,
          params
        );
        const total = countRow.total || 0;

        const [rows] = await db.query(
          `SELECT id, name, country, city, ranking, website, image_url, fees, courses, scholarships,
                  min_ielts_score, min_sat_score, scholarship_name, scholarship_amount, scholarship_type,
                  scholarship_eligibility_note, overview, facilities, admissions, location, contact
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
    },

    getUniversityDetail: async (req, res) => {
      try {
        const [rows] = await db.query(
          `SELECT id, name, country, city, ranking, website, overview, courses, fees,
                  facilities, scholarships, admissions, location, contact, image_url,
                  min_ielts_score, min_sat_score, scholarship_name, scholarship_amount, scholarship_type,
                  scholarship_eligibility_note
           FROM universities
           WHERE id = ?`,
          [req.params.id]
        );

        if (!rows.length) {
          return res.status(404).json({ message: "University not found" });
        }

        return res.json({ university: rows[0] });
      } catch (err) {
        console.error("UNIVERSITY DETAIL ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    getScholarshipRecommendations: async (req, res) => {
      try {
        const [[academic]] = await db.query(
          `SELECT gpa, ielts_score, toefl_score, gre_score, gmat_score, sat_score, field_of_study
           FROM user_academics
           WHERE user_id = ?`,
          [req.user.id]
        );

        const [[preferences]] = await db.query(
          `SELECT degree_level, field_of_study, preferred_countries, annual_budget, preferred_intake
           FROM user_preferences
           WHERE user_id = ?`,
          [req.user.id]
        );

        const country = firstCountry(preferences?.preferred_countries);
        const whereClause = country ? "WHERE country LIKE ?" : "";
        const queryParams = country ? [`%${country}%`] : [];

        const [universities] = await db.query(
          `SELECT id, name, country, city, ranking, website, image_url, scholarships, courses, fees,
                  min_ielts_score, min_sat_score, scholarship_name, scholarship_amount, scholarship_type,
                  scholarship_eligibility_note
           FROM universities
           ${whereClause}
           ORDER BY ranking IS NULL, ranking ASC, name ASC
           LIMIT 40`,
          queryParams
        );

        const gpa = toNumber(academic?.gpa);
        const ielts = toNumber(academic?.ielts_score);
        const toefl = toNumber(academic?.toefl_score);
        const gre = toNumber(academic?.gre_score);
        const gmat = toNumber(academic?.gmat_score);
        const sat = toNumber(academic?.sat_score);

        if (gpa !== null && gpa < 3) {
          return res.json({
            profile_used: {
              degree_level: preferences?.degree_level || null,
              field_of_study: preferences?.field_of_study || academic?.field_of_study || null,
              preferred_countries: preferences?.preferred_countries || null,
              annual_budget: preferences?.annual_budget || null,
              gpa: academic?.gpa || null,
              ielts_score: ielts,
              toefl_score: academic?.toefl_score || null,
              gre_score: academic?.gre_score || null,
              gmat_score: academic?.gmat_score || null,
              sat_score: academic?.sat_score || null,
            },
            recommendations: [],
            eligibility_message: "Scholarships are only shown for students with GPA 3.0 or above.",
          });
        }

        const scoreFromProfile =
          (gpa !== null ? Math.min(40, (gpa / 4) * 40) : 0) +
          (ielts !== null ? Math.min(20, (ielts / 9) * 20) : 0) +
          (toefl !== null ? Math.min(20, (toefl / 120) * 20) : 0) +
          (gre !== null ? Math.min(10, (gre / 340) * 10) : 0) +
          (gmat !== null ? Math.min(10, (gmat / 800) * 10) : 0);

        const preferredField = (preferences?.field_of_study || academic?.field_of_study || "").toLowerCase();

        const recommendations = universities.map((uni) => {
          const reasons = [];
          let fitScore = 0;
          const courseText = String(uni.courses || "").toLowerCase();
          const countryText = String(uni.country || "").toLowerCase();
          const feeAmount = parseFeeAmount(uni.fees);
          const budget = toNumber(preferences?.annual_budget);
          const minIelts = toNumber(uni.min_ielts_score);
          const minSat = toNumber(uni.min_sat_score);
          const scholarshipText = String(uni.scholarships || "").trim();
          const scholarshipName = String(uni.scholarship_name || "").trim();
          const scholarshipType = String(uni.scholarship_type || "").trim().toLowerCase();
          const scholarshipNote = String(uni.scholarship_eligibility_note || "").trim();
          const hasStructuredScholarship =
            !!scholarshipName
            || !!scholarshipText
            || !!scholarshipNote
            || toNumber(uni.scholarship_amount) !== null
            || ["fixed_amount", "percentage_waiver", "full_tuition"].includes(scholarshipType);

          if (!hasStructuredScholarship) {
            return null;
          }

          if (minIelts !== null) {
            if (ielts === null || ielts < minIelts) {
              return null;
            }
            reasons.push(`Meets IELTS requirement (${minIelts}+)`);
          }

          if (minSat !== null) {
            if (sat === null || sat < minSat) {
              return null;
            }
            reasons.push(`Meets SAT requirement (${minSat}+)`);
          }

          if (gpa !== null) {
            const gpaScore = Math.min(32, (gpa / 4) * 32);
            fitScore += gpaScore;
            if (gpa >= 3.7) reasons.push("High GPA fit");
            else if (gpa >= 3.2) reasons.push("Solid academic profile");
          }

          if (ielts !== null || toefl !== null) {
            const languageScore =
              (ielts !== null ? Math.min(16, (ielts / 9) * 16) : 0) +
              (toefl !== null ? Math.min(16, (toefl / 120) * 16) : 0);
            fitScore += Math.min(18, languageScore);

            if (ielts !== null && ielts >= 7) reasons.push("Strong IELTS score");
            if (toefl !== null && toefl >= 95) reasons.push("Strong TOEFL score");
          }

          if (gre !== null || gmat !== null) {
            const examScore =
              (gre !== null ? Math.min(8, (gre / 340) * 8) : 0) +
              (gmat !== null ? Math.min(8, (gmat / 800) * 8) : 0);
            fitScore += Math.min(10, examScore);

            if (gre !== null && gre >= 315) reasons.push("Competitive GRE profile");
            if (gmat !== null && gmat >= 650) reasons.push("Competitive GMAT profile");
          }

          if (preferredField && courseText.includes(preferredField)) {
            fitScore += 14;
            reasons.push("Intended subject match");
          }

          if (country && countryText.includes(String(country).toLowerCase())) {
            fitScore += 10;
            reasons.push("Country preference match");
          }

          if (budget !== null && feeAmount !== null) {
            if (feeAmount <= budget) {
              fitScore += 10;
              reasons.push("Budget-compatible");
            } else if (feeAmount <= budget * 1.2) {
              fitScore += 4;
              reasons.push("Slightly above budget but still possible");
            }
          }

          const rankScore = uni.ranking ? Math.max(0, 16 - Math.min(16, Math.floor(uni.ranking / 10))) : 6;
          fitScore += rankScore;
          if (uni.ranking && uni.ranking <= 50) reasons.push("Highly ranked university");

          fitScore += Math.min(8, scoreFromProfile * 0.08);
          fitScore = Math.round(Math.min(100, fitScore));
          const tier = scholarshipTier(fitScore);
          let scholarshipCoverage = formatScholarshipCoverage(uni.scholarship_amount, uni.scholarship_type);
          if (!scholarshipCoverage && scholarshipType === "percentage_waiver") {
            scholarshipCoverage = "Percentage tuition waiver";
          } else if (!scholarshipCoverage && scholarshipType === "fixed_amount") {
            scholarshipCoverage = "Fixed scholarship amount";
          } else if (!scholarshipCoverage && scholarshipType === "full_tuition") {
            scholarshipCoverage = "Full tuition";
          } else if (!scholarshipCoverage) {
            scholarshipCoverage = scholarshipText || scholarshipNote || tier.coverage;
          }

          return {
            university_id: uni.id,
            university_name: uni.name,
            country: uni.country,
            city: uni.city,
            ranking: uni.ranking,
            website: uni.website,
            image_url: uni.image_url,
            scholarship_name: scholarshipName || tier.title,
            estimated_coverage: scholarshipCoverage,
            fit_score: fitScore,
            match_reasons: reasons.slice(0, 5),
            annual_fee_estimate: feeAmount,
            minimum_ielts_score: minIelts,
            minimum_sat_score: minSat,
            scholarship_amount: toNumber(uni.scholarship_amount),
            scholarship_type: uni.scholarship_type || null,
            scholarship_eligibility_note: scholarshipNote || null,
            note: scholarshipText || scholarshipNote || "Scholarship details are available for this university.",
          };
        }).filter(Boolean).sort((a, b) => b.fit_score - a.fit_score || (a.ranking || 9999) - (b.ranking || 9999));

        return res.json({
          profile_used: {
            degree_level: preferences?.degree_level || null,
            field_of_study: preferences?.field_of_study || academic?.field_of_study || null,
            preferred_countries: preferences?.preferred_countries || null,
            annual_budget: preferences?.annual_budget || null,
            gpa: academic?.gpa || null,
            ielts_score: ielts,
            toefl_score: academic?.toefl_score || null,
            gre_score: academic?.gre_score || null,
            gmat_score: academic?.gmat_score || null,
            sat_score: academic?.sat_score || null,
          },
          recommendations,
        });
      } catch (err) {
        console.error("SCHOLARSHIP RECOMMENDATION ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    createUniversity: async (req, res) => {
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
          min_ielts_score,
          min_sat_score,
          scholarship_name,
          scholarship_amount,
          scholarship_type,
          scholarship_eligibility_note,
        } = req.body;

        if (!name || !country) {
          return res.status(400).json({ message: "name and country are required" });
        }

        const [result] = await db.query(
          `INSERT INTO universities
            (name, country, city, ranking, website, overview, courses, fees, facilities, scholarships, admissions, location, contact, image_url, min_ielts_score, min_sat_score, scholarship_name, scholarship_amount, scholarship_type, scholarship_eligibility_note)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
            toNumber(min_ielts_score),
            toNumber(min_sat_score),
            scholarship_name || null,
            toNumber(scholarship_amount),
            scholarship_type || null,
            scholarship_eligibility_note || null,
          ]
        );

        let notifiedUsers = 0;
        if (String(scholarships || "").trim()) {
          notifiedUsers = await notifyUsersAboutScholarshipUpdate({
            universityId: result.insertId,
            universityName: name,
            country,
            scholarships,
            website,
          });
        }

        await logUniversityAudit({
          universityId: result.insertId,
          action: "created",
          editorUserId: req.user.id,
          editorRole: req.user.role,
          changedFields: [
            "name",
            "country",
            "city",
            "ranking",
            "website",
            "overview",
            "courses",
            "fees",
            "facilities",
            "scholarships",
            "admissions",
            "location",
            "contact",
            "image_url",
            "min_ielts_score",
            "min_sat_score",
            "scholarship_name",
            "scholarship_amount",
            "scholarship_type",
            "scholarship_eligibility_note",
          ],
        });

        return res.status(201).json({
          message: "University added",
          scholarship_notifications_sent: notifiedUsers,
        });
      } catch (err) {
        console.error("ADD UNIVERSITY ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    updateUniversity: async (req, res) => {
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
          min_ielts_score,
          min_sat_score,
          scholarship_name,
          scholarship_amount,
          scholarship_type,
          scholarship_eligibility_note,
        } = req.body;

        const [existingRows] = await db.query(
          `SELECT name, country, city, ranking, website, overview, courses, fees, facilities, scholarships,
                  admissions, location, contact, image_url, min_ielts_score, min_sat_score,
                  scholarship_name, scholarship_amount, scholarship_type, scholarship_eligibility_note
           FROM universities
           WHERE id = ?`,
          [req.params.id]
        );

        if (!existingRows.length) {
          return res.status(404).json({ message: "University not found" });
        }

        const existingUniversity = existingRows[0];
        const changedFields = [];
        const nextUniversity = {
          name,
          country,
          city: city || null,
          ranking: ranking || null,
          website: website || null,
          overview: overview || null,
          courses: courses || null,
          fees: fees || null,
          facilities: facilities || null,
          scholarships: scholarships || null,
          admissions: admissions || null,
          location: location || null,
          contact: contact || null,
          image_url: image_url || null,
          min_ielts_score: toNumber(min_ielts_score),
          min_sat_score: toNumber(min_sat_score),
          scholarship_name: scholarship_name || null,
          scholarship_amount: toNumber(scholarship_amount),
          scholarship_type: scholarship_type || null,
          scholarship_eligibility_note: scholarship_eligibility_note || null,
        };

        Object.entries(nextUniversity).forEach(([field, value]) => {
          const previousValue = existingUniversity[field] ?? null;
          const normalizedPrevious = previousValue === null ? null : String(previousValue);
          const normalizedNext = value === null ? null : String(value);
          if (normalizedPrevious !== normalizedNext) {
            changedFields.push(field);
          }
        });

        await db.query(
          `UPDATE universities
           SET name = ?, country = ?, city = ?, ranking = ?, website = ?, overview = ?, courses = ?, fees = ?,
               facilities = ?, scholarships = ?, admissions = ?, location = ?, contact = ?, image_url = ?,
               min_ielts_score = ?, min_sat_score = ?, scholarship_name = ?, scholarship_amount = ?,
               scholarship_type = ?, scholarship_eligibility_note = ?
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
            toNumber(min_ielts_score),
            toNumber(min_sat_score),
            scholarship_name || null,
            toNumber(scholarship_amount),
            scholarship_type || null,
            scholarship_eligibility_note || null,
            req.params.id,
          ]
        );

        if (changedFields.length) {
          await logUniversityAudit({
            universityId: Number(req.params.id),
            action: "updated",
            editorUserId: req.user.id,
            editorRole: req.user.role,
            changedFields,
          });
        }

        let notifiedUsers = 0;
        if (scholarshipTextChanged(existingUniversity.scholarships, scholarships) && String(scholarships || "").trim()) {
          notifiedUsers = await notifyUsersAboutScholarshipUpdate({
            universityId: req.params.id,
            universityName: name || existingUniversity.name,
            country: country || existingUniversity.country,
            scholarships,
            website: website || existingUniversity.website,
          });
        }

        return res.json({
          message: "University updated",
          scholarship_notifications_sent: notifiedUsers,
        });
      } catch (err) {
        console.error("UPDATE UNIVERSITY ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    deleteUniversity: async (req, res) => {
      try {
        const [existingRows] = await db.query("SELECT id FROM universities WHERE id = ?", [req.params.id]);
        if (!existingRows.length) {
          return res.status(404).json({ message: "University not found" });
        }

        await logUniversityAudit({
          universityId: Number(req.params.id),
          action: "deleted",
          editorUserId: req.user.id,
          editorRole: req.user.role,
          changedFields: [],
        });

        await db.query("DELETE FROM universities WHERE id = ?", [req.params.id]);
        return res.json({ message: "University deleted" });
      } catch (err) {
        console.error("DELETE UNIVERSITY ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },
  };
}
