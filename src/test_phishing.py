from phishing_detector import analyze_phishing


test_messages = [
    "Hi Rohit, the project meeting is scheduled for tomorrow at 10 AM.",

    "Your bank account will be blocked today. Confirm your password immediately.",

    "URGENT! Verify your account immediately by clicking https://fake-bank-login.com",

    "Please submit your assignment before Monday.",

    "Security alert! Unusual activity detected. Login now and verify your identity.",

    "Your Amazon order has been shipped and will arrive today."
]


for message in test_messages:

    result = analyze_phishing(message)

    print("\n" + "=" * 70)

    print("MESSAGE:")
    print(message)

    print(
        "\nPHISHING RISK SCORE:",
        result["risk_score"]
    )

    print(
        "Urgency Indicators:",
        result["urgency"]
    )

    print(
        "Credential Indicators:",
        result["credentials"]
    )

    print(
        "Account Threat Indicators:",
        result["account_threats"]
    )

    print(
        "Financial Indicators:",
        result["financial"]
    )

    print(
        "Action Indicators:",
        result["actions"]
    )

    print(
        "Detected URLs:",
        result["urls"]
    )


print("\n" + "=" * 70)