import pandas as pd

file_path = "dataset/phishing_url_dataset.txt"

data = pd.read_csv(file_path)

print("Dataset Loaded Successfully!")
print(data.head())

print("Total URLs:", len(data))

data.to_csv("dataset/cleaned_dataset.csv", index=False)

print("Cleaned Dataset Saved Successfully!")