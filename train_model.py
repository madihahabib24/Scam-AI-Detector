
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

print("Loading Dataset...")

data = pd.read_csv("dataset/cleaned_dataset.csv")

# Remove missing and duplicate records
data = data.dropna(subset=["URL", "Label"])
data["URL"] = data["URL"].astype(str).str.strip()
data = data[data["URL"] != ""]
data = data.drop_duplicates(subset=["URL"])

# Validate labels
data["Label"] = pd.to_numeric(data["Label"], errors="raise")

if set(data["Label"].unique()) != {0, 1}:
    raise ValueError("Dataset must contain labels 0 and 1")

X = data["URL"]
y = data["Label"].astype(int)

print("Total Records:", len(data))
print("Label Distribution:")
print(y.value_counts())

print("Splitting Dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("Training AI Model...")

vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(3, 5),
    max_features=10000
)

X_train_vector = vectorizer.fit_transform(X_train)
X_test_vector = vectorizer.transform(X_test)

model = LogisticRegression(max_iter=1000)

model.fit(X_train_vector, y_train)

print("Testing Model...")

predictions = model.predict(X_test_vector)

accuracy = accuracy_score(y_test, predictions)

print("\nModel Accuracy:", round(accuracy * 100, 2), "%")

print("\nClassification Report:")

print(classification_report(
    y_test,
    predictions,
    labels=[0, 1],
    target_names=["Phishing", "Legitimate"]
))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions, labels=[0, 1]))

joblib.dump(model, "scam_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("\nAI Model Saved Successfully!")
