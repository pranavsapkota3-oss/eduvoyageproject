import nodemailer from "nodemailer";

export function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

export function createEmailService() {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASSWORD,
    },
  });

  const baseFrom = `EduVoyage <${process.env.GMAIL_USER}>`;

  return {
    async sendOtpEmail(email, code) {
      await transporter.sendMail({
        from: baseFrom,
        to: email,
        subject: "Your EduVoyage verification code",
        text: `Your verification code is ${code}. It expires in 10 minutes.`,
      });
    },

    async sendResetEmail(email, code) {
      await transporter.sendMail({
        from: baseFrom,
        to: email,
        subject: "EduVoyage password reset code",
        text: `Your password reset code is ${code}. It expires in 10 minutes.`,
      });
    },

    async sendScholarshipAlertEmail({
      email,
      fullName,
      universityName,
      country,
      scholarships,
      website,
    }) {
      const subject = `New scholarship update for ${country} universities`;
      const scholarshipText = String(scholarships || "").trim();
      const recipientName = fullName || "Student";
      const text = [
        `Hello ${recipientName},`,
        "",
        `A scholarship update was added for ${universityName} in ${country}, which matches your study preference.`,
        "",
        "Scholarship details:",
        `${scholarshipText}`,
        "",
        website ? `University website: ${website}` : null,
        "Visit EduVoyage to review the university and scholarship details.",
      ]
        .filter(Boolean)
        .join("\n");

      const scholarshipHtml = scholarshipText
        .split(/\r?\n/)
        .filter(Boolean)
        .map((line) => `<div style="margin-bottom:8px;">${line}</div>`)
        .join("");

      const html = `
        <div style="margin:0;padding:32px 0;background:#f3f4f6;font-family:Segoe UI,Arial,sans-serif;color:#1f2937;">
          <div style="max-width:640px;margin:0 auto;background:#ffffff;border:1px solid #e5e7eb;border-radius:18px;overflow:hidden;">
            <div style="padding:20px 28px;background:#374151;color:#ffffff;">
              <div style="font-size:12px;letter-spacing:1.4px;text-transform:uppercase;opacity:0.78;">EduVoyage Notification</div>
              <div style="margin-top:8px;font-size:28px;font-weight:700;line-height:1.2;">Scholarship update available</div>
            </div>
            <div style="padding:28px;">
              <p style="margin:0 0 14px;font-size:16px;line-height:1.7;">Hello ${recipientName},</p>
              <p style="margin:0 0 20px;font-size:16px;line-height:1.7;color:#4b5563;">
                A new scholarship update was added for <strong style="color:#111827;">${universityName}</strong> in
                <strong style="color:#111827;">${country}</strong>, which matches the country you selected in your study preferences.
              </p>

              <div style="margin:0 0 22px;padding:18px;border:1px solid #d1d5db;border-radius:14px;background:#f9fafb;">
                <div style="font-size:12px;letter-spacing:1.2px;text-transform:uppercase;color:#6b7280;margin-bottom:10px;">Scholarship details</div>
                <div style="font-size:15px;line-height:1.7;color:#1f2937;">
                  ${scholarshipHtml || "<div>No scholarship summary was provided.</div>"}
                </div>
              </div>

              <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:22px;">
                <div style="padding:12px 14px;border-radius:12px;background:#f3f4f6;border:1px solid #e5e7eb;min-width:180px;">
                  <div style="font-size:12px;text-transform:uppercase;letter-spacing:1px;color:#6b7280;">University</div>
                  <div style="margin-top:6px;font-size:15px;font-weight:600;color:#111827;">${universityName}</div>
                </div>
                <div style="padding:12px 14px;border-radius:12px;background:#f3f4f6;border:1px solid #e5e7eb;min-width:140px;">
                  <div style="font-size:12px;text-transform:uppercase;letter-spacing:1px;color:#6b7280;">Country</div>
                  <div style="margin-top:6px;font-size:15px;font-weight:600;color:#111827;">${country}</div>
                </div>
              </div>

              ${
                website
                  ? `<a href="${website}" style="display:inline-block;padding:12px 18px;background:#4b5563;color:#ffffff;text-decoration:none;border-radius:10px;font-size:14px;font-weight:600;">Visit university website</a>`
                  : ""
              }

              <p style="margin:24px 0 0;font-size:14px;line-height:1.7;color:#6b7280;">
                Open EduVoyage to review the full university profile, compare options, and update your shortlist.
              </p>
            </div>
          </div>
        </div>
      `;

      await transporter.sendMail({
        from: baseFrom,
        to: email,
        subject,
        text,
        html,
      });
    },
  };
}
