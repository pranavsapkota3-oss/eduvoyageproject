CREATE TABLE IF NOT EXISTS user_documents (
  id INT NOT NULL AUTO_INCREMENT,
  user_id INT NOT NULL,
  file_name VARCHAR(255) NOT NULL,
  file_size VARCHAR(50) NULL,
  file_url VARCHAR(255) NULL,
  mime_type VARCHAR(100) NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT fk_user_documents_user
    FOREIGN KEY (user_id)
    REFERENCES users(id)
    ON DELETE CASCADE
);
