from flask import Flask, render_template, request  # type: ignore
import pickle
import pandas as pd  # type: ignore
from urllib.parse import urlparse

app = Flask(__name__)
model = pickle.load(open("phishing_model.pkl", "rb"))

# Define common phishing keywords
phishing_keywords = ['login', 'secure', 'account', 'bank', 'update', 'confirm']

def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    return {
        "length": len(url),
        "num_dots": url.count('.'),
        "num_slashes": url.count('/'),
        "num_urls": url.lower().count("http"),  # count both http and https
        "num_subdomains": len(hostname.split('.')) - 2 if hostname else 0,
        "has_phishing_keyword": int(any(keyword in url.lower() for keyword in phishing_keywords))
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']
    features = extract_features(url)
    df = pd.DataFrame([features])
    prediction = model.predict(df)[0]
    result = "Phishing" if prediction == 1 else "Legitimate"
    return render_template('index.html', prediction=result, url=url)

if __name__ == '__main__':
    app.run(debug=True)
