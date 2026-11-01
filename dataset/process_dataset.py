import pandas as pd

# Dataset file load
file_path = "dataset/phishing_url_dataset.txt"

# Read dataset
data = pd.read_csv(file_path)

# Check dataset
print("Dataset Loaded Successfully!")
print(data.head())

# Check total records
print("\nTotal URLs:", len(data))

# Save cleaned dataset
data.to_csv("dataset/cleaned_dataset.csv", index=False)

print("\nCleaned Dataset Saved Successfully!")