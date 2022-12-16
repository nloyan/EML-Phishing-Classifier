# A Machine Learning model to examine EML files and classify them as benign or malicious. By Nur Loyan

from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.ensemble import GradientBoostingClassifier
from imblearn.over_sampling import SMOTE
import numpy as np
import email
import csv


def load_dataset(csv_file):
    """Loads the dataset from a CSV file.

    Args:
        csv_file: The path to the CSV file.

    Returns:
        features: A list of features extracted from the .eml files.
        labels: A list of labels for each .eml file, where 1 represents a malicious file and 0 represents a benign file.
    """
    features = []
    labels = []

    # Open the CSV file and iterate through its rows
    with open(csv_file, "r") as f:
        reader = csv.reader(f)
        next(reader)  # Skip the header row
        for row in reader:
            # Extract the features from the .eml file
            eml_bytes = bytes(row[0], 'utf-8')
            eml_features = extract_features(eml_bytes)

            # Append the extracted features to the list of features
            features.append(eml_features)

            # Append the corresponding label to the list of labels
            label = row[1]
            if label == "malicious":
                labels.append(1)
            else:
                labels.append(0)

    return features, labels


def extract_features(eml_bytes):
    """Extracts features from an .eml file.

    Args:
        eml_bytes: A bytes object representing an .eml file.

    Returns:
        A list of features extracted from the .eml file.
    """
    # Parse the .eml file as an email object
    eml = email.message_from_bytes(bytes(eml_bytes))

    features = []

    # Extract the number of recipients of the email
    recipients = []
    if "To" in eml:
        recipients += eml["To"].split(", ")
    if "CC" in eml:
        recipients += eml["CC"].split(", ")
    if "BCC" in eml:
        recipients += eml["BCC"].split(", ")
    features.append(len(recipients))

    # Extract the length of the subject of the email
    subject = eml["Subject"]
    features.append(subject)

    # Extract the number of attachments in the email
    attachments = []
    for part in eml.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get("Content-Disposition") is None:
            continue
        attachments.append({
            "filename": part.get_filename(),
            "size": len(part.get_payload(decode=True)),
            "mime_type": part.get_content_type()
        })
    features.append(len(attachments))

    # Extract the IP address of the sender
    ip_address = None
    if "Received" in eml:
        received_header = eml["Received"]
        ip_address = received_header.split(" ")[-1]
    features.append(ip_address)

    return features


# Load the dataset of .eml files and their labels
emails, labels = load_dataset('C:/Users/nloya/Downloads/emails.csv')

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(emails, labels)

# Initialize the LabelEncoder
le = LabelEncoder()

# Fit the LabelEncoder on the string labels
le.fit(y_train)

# Transform the string labels to numerical values
y_train = le.transform(y_train)

# Create the imputer transformer
imputer = SimpleImputer(strategy='mean')

# Create the classifier
classifier = GradientBoostingClassifier(max_features=None)

# Create the pipeline
pipeline = Pipeline([('imputer', imputer), ('classifier', classifier)])

# over sampling

value_counts = np.unique(y_train, return_counts=True)
print(value_counts)

smote = SMOTE()
X_train, y_train = smote.fit_resample(X_train, y_train)

# Check the value counts of the y_train variable


# Fit the pipeline on the training data
pipeline.fit(X_train, y_train)

# Test the classifier on the testing data
accuracy = classifier.score(X_test, y_test)
print(f"Accuracy: {accuracy:.2f}")

# Load the .eml file to classify
with open("file.eml", "rb") as f:
    eml_bytes = f.read()

# Parse the .eml file into an email object
eml = email.message_from_bytes(eml_bytes)

# Extract features from the .eml file
features = extract_features(eml)

# Classify the .eml file as either malicious or benign
prediction = classifier.predict([features])
if prediction == 1:
    print("This .eml file is malicious.")
else:
    print("This .eml file is benign.")
