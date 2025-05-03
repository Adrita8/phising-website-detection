import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix
import re
from sklearn.metrics import precision_score, recall_score, f1_score


data = pd.read_excel("/content/3300data.xlsx")


def extract_features(url):
    features = []


    features.append(len(url))


    features.append(url.count('.'))


    features.append(url.count('/'))


    features.append(url.count('-'))


    subdomains = len(re.findall(r'\.', url.split('//')[1].split('/')[0])) - 1
    features.append(subdomains)


    phishing_keywords = ['login', 'secure', 'account', 'bank', 'update', 'confirm']
    features.append(int(any(keyword in url for keyword in phishing_keywords)))

    return features


X = np.array([extract_features(url) for url in data['URL']])


y = data['label']


X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)


model = LogisticRegression()
model.fit(X_train, y_train)


y_pred = model.predict(X_test)


print(f"Accuracy: {accuracy_score(y_test, y_pred)}")
print(f"Confusion Matrix:\n{confusion_matrix(y_test, y_pred)}")
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
print(f"Precision: {precision:.2f}")
print(f"Recall: {recall:.2f}")
print(f"F1 Score: {f1:.2f}")


print(f"Model Coefficients: {model.coef_}")


from sklearn.metrics import roc_curve, roc_auc_score
y_prob = model.predict_proba(X_test)[:, 1]
fpr, tpr, _ = roc_curve(y_test, y_prob)
auc_score = roc_auc_score(y_test, y_prob)
plt.plot(fpr, tpr, label=f"AUC = {auc_score:.2f}")
plt.plot([0, 1], [0, 1], 'k--')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('ROC Curve')
plt.legend()
plt.show()


import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.metrics import ConfusionMatrixDisplay

ConfusionMatrixDisplay.from_estimator(model, X_test, y_test, cmap='Blues')
plt.title('Confusion Matrix')
plt.show()



data['label'].value_counts().plot(kind='bar', color=['blue', 'orange'])
plt.title('Class Distribution')
plt.xlabel('Class (0=Legitimate, 1=Phishing)')
plt.ylabel('Count')
plt.show()

user_url = input("Enter a URL to check: ")
user_features = np.array(extract_features(user_url)).reshape(1, -1)
user_prediction = model.predict(user_features)[0]

if user_prediction == 1:
    print("The URL is predicted to be phishing.")
else:
    print("The URL is predicted to be legitimate.")
