import os
import joblib

from phishing_detector import analyze_phishing


# -----------------------------------
# LOAD TRAINED SPAM MODEL
# -----------------------------------

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "spam_model.pkl"
)

spam_model = joblib.load(MODEL_PATH)


# -----------------------------------
# EMAIL ANALYSIS FUNCTION
# -----------------------------------

def analyze_email(text):

    # -----------------------------------
    # SPAM MODEL ANALYSIS
    # -----------------------------------

    probabilities = spam_model.predict_proba(
        [text]
    )[0]

    spam_probability = float(
        probabilities[1] * 100
    )


    # -----------------------------------
    # PHISHING ANALYSIS
    # -----------------------------------

    phishing_result = analyze_phishing(
        text
    )

    phishing_risk = phishing_result[
        "risk_score"
    ]


    # -----------------------------------
    # COUNT STRONG PHISHING INDICATORS
    # -----------------------------------

    strong_indicator_count = 0

    if phishing_result["credentials"]:
        strong_indicator_count += 1

    if phishing_result["account_threats"]:
        strong_indicator_count += 1

    if phishing_result["actions"]:
        strong_indicator_count += 1

    suspicious_urls = [
    analysis
    for analysis in phishing_result["url_analysis"]
    if analysis["risk_score"] >= 10
]


    if suspicious_urls:
      strong_indicator_count += 1


    # -----------------------------------
    # FINAL CLASSIFICATION
    # -----------------------------------

    if (
        phishing_risk >= 50
        and strong_indicator_count >= 2
    ):
        classification = "PHISHING"

    elif spam_probability >= 50:
        classification = "SPAM"

    else:
        classification = "SAFE"


    # -----------------------------------
    # RETURN ANALYSIS RESULT
    # -----------------------------------

    return {
        "classification": classification,
        "spam_probability": round(
            spam_probability,
            2
        ),
        "phishing_risk": phishing_risk,
        "strong_indicator_count": strong_indicator_count,
        "phishing_details": phishing_result
    }