What it does
Trains a machine learning model to classify emails as Phishing or Safe
Uses TF-IDF to convert email text into numerical features
Trained with Logistic Regression on a combined dataset (Enron, CEAS, Nazario, SpamAssassin, etc.)
Achieves 98% accuracy
Displays confusion matrix and classification report
Tests prediction on a custom sample email
Dataset
Phishing Email Dataset (Kaggle) — combines Enron, Ling, CEAS, Nazario, Nigerian Fraud, and SpamAssassin datasets. ~82,000 labeled emails.

How to run
pip install pandas scikit-learn
Download dataset from Kaggle and place phishing_email.csv in the same folder
python phishing_model.py
Results
Accuracy: 98.04%
Precision/Recall: 0.98 for both classes
Concepts used
Natural Language Processing (TF-IDF)
Supervised machine learning classification
Train/test split methodology
Model evaluation (confusion matrix, precision, recall, F1-score)
