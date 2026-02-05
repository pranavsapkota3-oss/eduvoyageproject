CREATE TABLE IF NOT EXISTS user_academics (
  user_id INT NOT NULL,
  highest_level VARCHAR(50) NULL,
  gpa VARCHAR(20) NULL,
  school_name VARCHAR(150) NULL,
  graduation_year VARCHAR(10) NULL,
  field_of_study VARCHAR(150) NULL,
  ielts_score VARCHAR(20) NULL,
  toefl_score VARCHAR(20) NULL,
  gre_score VARCHAR(20) NULL,
  gmat_score VARCHAR(20) NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id),
  CONSTRAINT fk_user_academics_user
    FOREIGN KEY (user_id)
    REFERENCES users(id)
    ON DELETE CASCADE
);
