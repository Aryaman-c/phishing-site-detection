import sys
import os
import pickle
from feature import FeatureExtraction

MODEL_PATH = os.path.join('pickle', 'model.pkl')

def main():
    if len(sys.argv) != 2:
        print('Usage: python predict_url.py <url>')
        sys.exit(1)
    url = sys.argv[1]
    # Extract features
    extractor = FeatureExtraction(url)
    features = extractor.getFeaturesList()
    # Load model
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    # Predict
    prediction = model.predict([features])[0]
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba([features])[0]
        # Dynamically determine which class is 'safe' and which is 'phishing'
        classes = list(model.classes_)
        safe_label = max(classes)
        phishing_label = min(classes)
        safe_idx = classes.index(safe_label)
        phishing_idx = classes.index(phishing_label)
        safe_pct = proba[safe_idx] * 100
        phishing_pct = proba[phishing_idx] * 100
        if prediction == safe_label:
            print(f'URL is SAFE: {url} ({safe_pct:.1f}% confidence)')
        else:
            print(f'URL is PHISHING: {url} ({phishing_pct:.1f}% confidence)')
    else:
        if prediction == 1:
            print(f'URL is SAFE: {url}')
        else:
            print(f'URL is PHISHING: {url}')

if __name__ == '__main__':
    main() 