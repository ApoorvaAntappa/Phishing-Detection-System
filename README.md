# Real-Time Phishing Detection System using Wireshark and Machine Learning

## Overview
A machine learning based phishing detection system that monitors network traffic and detects suspicious URLs, domains, and phishing activities.

## Features
- Real-time packet monitoring using Wireshark/TShark
- URL phishing detection using Machine Learning
- Email phishing detection
- Flask dashboard for monitoring alerts
- MySQL database for storing detection history

## Technologies Used

- Python
- Flask
- Machine Learning
- Wireshark
- PyShark
- Scikit-learn
- MySQL
- HTML/CSS

## Machine Learning Model

Random Forest Classifier is used for phishing URL classification.

## Project Structure


PhishingDetectionSystem/
│
├── app.py
├── detection/
├── packet_capture/
├── database/
├── templates/
├── requirements.txt
└── README.md

## Installation


pip install -r requirements.txt

## Run Application


python app.py


Save it.
