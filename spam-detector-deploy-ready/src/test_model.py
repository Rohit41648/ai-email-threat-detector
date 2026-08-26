import joblib


# Load trained spam detection model
model = joblib.load(
    "models/spam_model.pkl"
)


test_messages = [
    "Hi Rohit, the project meeting is scheduled for tomorrow at 10 AM.",

    "Congratulations! You have won a FREE cash prize. Claim now!",

    "URGENT! Your account has been suspended. Verify your details immediately.",

    "Please submit your assignment before Monday.",

    "You have been selected for a reward of Rs 50,000. Click the link to receive your money.",

    "Dear student, your placement interview has been scheduled for Friday at 2 PM.",

    "Your bank account will be blocked today. Confirm your password immediately."
]


for message in test_messages:

    prediction = model.predict([message])[0]

    probabilities = model.predict_proba([message])[0]

    safe_probability = probabilities[0]
    spam_probability = probabilities[1]

    print("\n" + "=" * 60)

    print("MESSAGE:")
    print(message)

    print(
        "\nPREDICTION:",
        "SPAM" if prediction == 1 else "SAFE"
    )

    print(
        f"Safe Probability: {safe_probability * 100:.2f}%"
    )

    print(
        f"Spam Probability: {spam_probability * 100:.2f}%"
    )


print("\n" + "=" * 60)