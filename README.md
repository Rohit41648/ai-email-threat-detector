# AI Email Threat Detector

A hybrid machine learning and rule-based system that analyzes email content for spam and phishing risk in real time.

**Live demo:** _(add your Streamlit Cloud link here after deploying)_

## Features

- **Spam detection** — TF-IDF + Multinomial Naive Bayes classifier trained on the SMS Spam Collection dataset (~98% accuracy)
- **Phishing risk scoring** — Regex-based rule engine that detects:
  - Urgency language ("act now", "within 24 hours")
  - Credential requests ("verify your password", "confirm your identity")
  - Account threat language ("account suspended", "unusual activity")
  - Financial language ("bank account", "payment details")
  - Suspicious action prompts ("click here", "login now")
  - Suspicious URLs (non-HTTPS, suspicious keywords)
- **Real-time analysis** via an interactive Streamlit interface

## Tech Stack

Python, scikit-learn, Streamlit, joblib, regex

## Running Locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Project Structure

```
├── app.py                    # Streamlit UI
├── src/
│   ├── email_analyzer.py     # Combines spam model + phishing rules
│   ├── phishing_detector.py  # Rule-based phishing pattern detection
│   └── url_analyzer.py       # URL structural risk analysis
├── models/
│   └── spam_model.pkl        # Trained TF-IDF + Naive Bayes pipeline
└── data/
    └── SMSSpamCollection     # Training dataset
```
