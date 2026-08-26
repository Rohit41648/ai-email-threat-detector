import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib


# Load the SMS Spam Collection dataset
data = pd.read_csv(
    "data/SMSSpamCollection",
    sep="\t",
    names=["label", "message"]
)


print("Dataset loaded successfully!")

print("\nFirst 5 rows:")
print(data.head())

print("\nDataset shape:")
print(data.shape)

print("\nClass distribution:")
print(data["label"].value_counts())

print("\nMissing values:")
print(data.isnull().sum())
from sklearn.model_selection import train_test_split


# Convert text labels into numerical labels
data["label"] = data["label"].map({
    "ham": 0,
    "spam": 1
})


print("\nLabels after conversion:")
print(data["label"].value_counts())


# Define input features and target
X = data["message"]
y = data["label"]


# Split dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


print("\nTraining data size:")
print(len(X_train))

print("\nTesting data size:")
print(len(X_test))

print("\nTraining class distribution:")
print(y_train.value_counts())

print("\nTesting class distribution:")
print(y_test.value_counts())
# -----------------------------------
# CREATE MACHINE LEARNING PIPELINE
# -----------------------------------

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            stop_words="english",
            max_features=5000,
            ngram_range=(1, 2)
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced"
        )
    )
])


print("\nMachine learning pipeline created!")
# -----------------------------------
# TRAIN THE MODEL
# -----------------------------------

print("\nTraining model...")

model.fit(X_train, y_train)

print("Model training completed!")
# -----------------------------------
# EVALUATE THE MODEL
# -----------------------------------

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)


print("\nModel Accuracy:")
print(f"{accuracy * 100:.2f}%")


print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        target_names=["Safe", "Spam"]
    )
)


print("\nConfusion Matrix:")
print(
    confusion_matrix(
        y_test,
        predictions
    )
)
# -----------------------------------
# SAVE TRAINED MODEL
# -----------------------------------

joblib.dump(
    model,
    "models/spam_model.pkl"
)

print("\nModel saved successfully!")