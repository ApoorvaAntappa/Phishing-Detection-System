-- Schema for PhishingDetectionSystem

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS detected_urls (
  id INT AUTO_INCREMENT PRIMARY KEY,
  url TEXT NOT NULL,
  domain VARCHAR(255),
  status VARCHAR(50),
  risk_score FLOAT,
  features JSON,
  extra TEXT,
  detected_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert a default admin user (password stored in plaintext for demo; change in production)
INSERT INTO users (username, password)
SELECT 'admin', 'admin123' FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM users WHERE username='admin');
