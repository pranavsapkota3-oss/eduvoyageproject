ALTER TABLE universities
  ADD COLUMN IF NOT EXISTS overview TEXT NULL,
  ADD COLUMN IF NOT EXISTS courses TEXT NULL,
  ADD COLUMN IF NOT EXISTS fees TEXT NULL,
  ADD COLUMN IF NOT EXISTS facilities TEXT NULL,
  ADD COLUMN IF NOT EXISTS scholarships TEXT NULL,
  ADD COLUMN IF NOT EXISTS scholarship_name VARCHAR(255) NULL,
  ADD COLUMN IF NOT EXISTS scholarship_amount DECIMAL(10,2) NULL,
  ADD COLUMN IF NOT EXISTS scholarship_type VARCHAR(40) NULL,
  ADD COLUMN IF NOT EXISTS scholarship_eligibility_note TEXT NULL,
  ADD COLUMN IF NOT EXISTS min_ielts_score DECIMAL(3,1) NULL,
  ADD COLUMN IF NOT EXISTS min_sat_score INT NULL,
  ADD COLUMN IF NOT EXISTS admissions TEXT NULL,
  ADD COLUMN IF NOT EXISTS location VARCHAR(150) NULL,
  ADD COLUMN IF NOT EXISTS contact VARCHAR(150) NULL,
  ADD COLUMN IF NOT EXISTS image_url VARCHAR(255) NULL;

CREATE TABLE IF NOT EXISTS expense_plans (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  university_id INT NOT NULL,
  applied TINYINT(1) NOT NULL DEFAULT 0,
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
);

CREATE TABLE IF NOT EXISTS expense_entries (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  university_id INT NOT NULL,
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
);

ALTER TABLE user_documents
  ADD COLUMN IF NOT EXISTS review_status VARCHAR(20) NOT NULL DEFAULT 'pending',
  ADD COLUMN IF NOT EXISTS review_comment TEXT NULL,
  ADD COLUMN IF NOT EXISTS reviewed_by INT NULL,
  ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMP NULL DEFAULT NULL;

CREATE TABLE IF NOT EXISTS applications (
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
);

CREATE TABLE IF NOT EXISTS counseling_requests (
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
);

CREATE TABLE IF NOT EXISTS university_audit_logs (
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
);
