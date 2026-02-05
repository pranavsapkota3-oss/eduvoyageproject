CREATE TABLE IF NOT EXISTS user_preferences (
  user_id INT NOT NULL,
  degree_level VARCHAR(50) NULL,
  field_of_study VARCHAR(150) NULL,
  preferred_countries VARCHAR(200) NULL,
  annual_budget VARCHAR(50) NULL,
  preferred_intake VARCHAR(50) NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id),
  CONSTRAINT fk_user_preferences_user
    FOREIGN KEY (user_id)
    REFERENCES users(id)
    ON DELETE CASCADE
);
