CREATE TABLE IF NOT EXISTS universities (
  id INT NOT NULL AUTO_INCREMENT,
  name VARCHAR(200) NOT NULL,
  country VARCHAR(100) NOT NULL,
  city VARCHAR(100) NULL,
  ranking INT NULL,
  website VARCHAR(255) NULL,
  overview TEXT NULL,
  courses TEXT NULL,
  fees TEXT NULL,
  facilities TEXT NULL,
  scholarships TEXT NULL,
  admissions TEXT NULL,
  location VARCHAR(150) NULL,
  contact VARCHAR(150) NULL,
  image_url VARCHAR(255) NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
);
