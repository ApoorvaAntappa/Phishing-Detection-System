from detection.feature_extractor import extract_features
from model.ml_detector import predict_url

url = "https://paypal-login-security.xyz/login"

features = extract_features(url)

print("DEBUG FEATURES:", features)   # optional debug

result = predict_url(features)

print("URL:", url)
print("RESULT:", result)