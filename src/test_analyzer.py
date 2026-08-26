from email_analyzer import analyze_email


test_messages = [
    "Hi Rohit, the project meeting is scheduled for tomorrow at 10 AM.",

    "Congratulations! You have won a FREE cash prize. Claim now!",

    "Your bank account will be blocked today. Confirm your password immediately.",

    "Please submit your assignment before Monday.",

    "URGENT! Verify your account immediately by clicking https://fake-bank-login.com",

    "Dear student, your placement interview has been scheduled for Friday at 2 PM.",

    "Security alert! Unusual activity detected. Login now and verify your identity.",

    "Your Amazon order has been shipped and will arrive today."
]


for message in test_messages:

    result = analyze_email(message)

    print("\n" + "=" * 70)

    print("MESSAGE:")
    print(message)

    print(
        "\nFINAL CLASSIFICATION:",
        result["classification"]
    )

    print(
        "Spam Probability:",
        result["spam_probability"]
    )

    print(
        "Phishing Risk Score:",
        result["phishing_risk"]
    )

    print(
        "Strong Indicator Count:",
        result["strong_indicator_count"]
    )

    details = result["phishing_details"]

    print("\nDETECTED INDICATORS:")

    print(
        "Urgency:",
        details["urgency"]
    )

    print(
        "Credentials:",
        details["credentials"]
    )

    print(
        "Account Threats:",
        details["account_threats"]
    )

    print(
        "Financial:",
        details["financial"]
    )

    print(
        "Actions:",
        details["actions"]
    )

    print(
        "URLs:",
        details["urls"]
    )


print("\n" + "=" * 70)