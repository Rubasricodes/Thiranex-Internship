import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

# ─────────────────────────────────────────────
# STEP 1: LOAD THE DATA
# ─────────────────────────────────────────────

df = pd.read_csv("phishing_email.csv")

print("Total emails:", len(df))
print("Label distribution:\n", df['label'].value_counts())

# ─────────────────────────────────────────────
# STEP 2: CHECK COLUMNS AND CLEAN MISSING DATA
# ─────────────────────────────────────────────

print("\nColumns in this file:", df.columns.tolist())

# This combined file only has 'text' and 'label' columns (no separate subject/body)
# So we just clean up the text column
df['text_combined'] = df['text_combined'].fillna('')

# ─────────────────────────────────────────────
# STEP 3: SPLIT INTO TRAIN AND TEST SETS
# ─────────────────────────────────────────────

X = df['text_combined']
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print(f"\nTraining on {len(X_train)} emails, testing on {len(X_test)} emails")

# ─────────────────────────────────────────────
# STEP 4: CONVERT TEXT INTO NUMBERS (TF-IDF)
# ─────────────────────────────────────────────

vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# ─────────────────────────────────────────────
# STEP 5: TRAIN THE MODEL
# ─────────────────────────────────────────────

model = LogisticRegression(max_iter=1000)
model.fit(X_train_vec, y_train)

print("\n✅ Model training complete!")

# ─────────────────────────────────────────────
# STEP 6: TEST THE MODEL
# ─────────────────────────────────────────────

y_pred = model.predict(X_test_vec)

# ─────────────────────────────────────────────
# STEP 7: EVALUATE RESULTS
# ─────────────────────────────────────────────

accuracy = accuracy_score(y_test, y_pred)
print(f"\n📊 Accuracy: {accuracy * 100:.2f}%")

print("\n📋 Confusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(cm)
print("""
Format:
[[True Negatives   False Positives]
 [False Negatives  True Positives]]
""")

print("📈 Detailed Report:")
print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))

# ─────────────────────────────────────────────
# STEP 8: TEST ON A NEW CUSTOM EMAIL
# ─────────────────────────────────────────────

def predict_email(text):
    vec = vectorizer.transform([text])
    prediction = model.predict(vec)[0]
    probability = model.predict_proba(vec)[0]
    label = "🚨 PHISHING" if prediction == 1 else "✅ SAFE"
    confidence = max(probability) * 100
    return label, confidence

sample_email = "Urgent! Your account has been suspended. Click here immediately to verify your identity: http://fake-bank-login.com"
label, confidence = predict_email(sample_email)
print(f"\n🧪 Test Email Prediction: {label} (Confidence: {confidence:.1f}%)")
