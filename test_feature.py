from detection.feature_extractor import extract_features

url = "https://paypal-login-security.xyz/login"

features = extract_features(url)

print("URL:")
print(url)

print("\nFeatures:")
print(features)