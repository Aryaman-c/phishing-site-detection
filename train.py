import os
import pickle
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, f1_score

DATASET_PATH = 'phishing_50k.csv' if os.path.exists('phishing_50k.csv') else 'phishing.csv'
MODEL_DIR = 'pickle'
MODEL_PATH = os.path.join(MODEL_DIR, 'model.pkl')

FEATURE_NAMES = [
    'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//',
    'PrefixSuffix-', 'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon',
    'NonStdPort', 'HTTPSDomainURL', 'RequestURL', 'AnchorURL',
    'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail', 'AbnormalURL',
    'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
    'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording',
    'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage',
    'StatsReport'
]

def train_and_save_model():
    print(f"Loading dataset from {DATASET_PATH}...")
    df = pd.read_csv(DATASET_PATH)
    
    if 'Index' in df.columns:
        df = df.drop('Index', axis=1)

    X = df.drop('class', axis=1).values
    y = df['class'].values

    print(f"Dataset shape: {df.shape} (URLs count: {len(df):,})")
    
    # 80-20 train-test split with stratification
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training Random Forest classifier...")
    # Random Forest Classifier optimized for malicious URL detection
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        min_samples_split=2,
        random_state=42,
        class_weight='balanced',
        n_jobs=-1
    )
    rf.fit(X_train, y_train)

    # Evaluate
    y_pred = rf.predict(X_test)
    f1 = f1_score(y_test, y_pred, average='weighted')
    print("=" * 60)
    print(f"Model: Random Forest Classifier")
    print(f"Weighted F1-Score: {f1 * 100:.2f}% (Target: ~97%)")
    print("=" * 60)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Phishing (-1)', 'Legitimate (1)'], digits=4))

    # Save model to pickle/model.pkl
    os.makedirs(MODEL_DIR, exist_ok=True)
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(rf, f)
    print(f"Trained Random Forest model successfully saved to {MODEL_PATH}")

if __name__ == '__main__':
    train_and_save_model()
