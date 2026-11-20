MYSQL_HOST = "localhost"
MYSQL_USER = "root"
MYSQL_PASSWORD = "Apoorva@16"
MYSQL_DB = "phishing_detection"

# Trusted domains that should always be classified SAFE (lowercase)
TRUSTED_DOMAINS = {
	"www.whatsapp.com",
	"whatsapp.com",
	"www.google.com",
	"google.com",
	"www.facebook.com",
	"facebook.com",
	"www.amazon.com",
	"amazon.com",
	"www.amazon.in",
	"amazon.in",
}

# Confidence threshold below which predictions should be reviewed manually
CONFIDENCE_REVIEW_THRESHOLD = 0.7