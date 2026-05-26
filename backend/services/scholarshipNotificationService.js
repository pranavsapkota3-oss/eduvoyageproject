export function createScholarshipNotificationService({ db, sendScholarshipAlertEmail }) {
  const COUNTRY_ALIASES = {
    usa: "united states",
    us: "united states",
    "u.s.a.": "united states",
    "u.s.": "united states",
    america: "united states",
    uk: "united kingdom",
    uae: "united arab emirates",
  };

  const normalizeCountryName = (value) => {
    const normalized = String(value || "").trim().toLowerCase();
    return COUNTRY_ALIASES[normalized] || normalized;
  };

  const splitPreferredCountries = (value) =>
    String(value || "")
      .split(",")
      .map((item) => normalizeCountryName(item))
      .filter(Boolean);

  const scholarshipTextChanged = (previousValue, nextValue) =>
    String(previousValue || "").trim() !== String(nextValue || "").trim();

  const notifyUsersAboutScholarshipUpdate = async ({
    universityId,
    universityName,
    country,
    scholarships,
    website,
  }) => {
    const scholarshipText = String(scholarships || "").trim();
    const normalizedCountry = normalizeCountryName(country);

    if (!scholarshipText || !normalizedCountry) {
      return 0;
    }

    if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) {
      console.warn("SCHOLARSHIP ALERT EMAIL SKIPPED: Gmail credentials are missing.");
      return 0;
    }

    try {
      const [users] = await db.query(
        `SELECT u.id, u.full_name, u.email, up.preferred_countries
         FROM users u
         INNER JOIN user_preferences up ON up.user_id = u.id
         LEFT JOIN user_settings us ON us.user_id = u.id
         WHERE u.is_active = 1
           AND u.role = 'student'
           AND u.email IS NOT NULL
           AND up.preferred_countries IS NOT NULL
           AND (us.user_id IS NULL OR (us.email_notifications = 1 AND us.scholarship_alerts = 1))`
      );

      const matchingUsers = users.filter((user) =>
        splitPreferredCountries(user.preferred_countries).includes(normalizedCountry)
      );

      for (const user of matchingUsers) {
        try {
          await sendScholarshipAlertEmail({
            email: user.email,
            fullName: user.full_name,
            universityName,
            country,
            scholarships: scholarshipText,
            website,
          });
        } catch (mailErr) {
          console.error(
            `SCHOLARSHIP ALERT EMAIL ERROR: user=${user.id}, university=${universityId}`,
            mailErr
          );
        }
      }

      return matchingUsers.length;
    } catch (err) {
      console.error("SCHOLARSHIP ALERT LOOKUP ERROR:", err);
      return 0;
    }
  };

  return {
    normalizeCountryName,
    splitPreferredCountries,
    scholarshipTextChanged,
    notifyUsersAboutScholarshipUpdate,
  };
}
