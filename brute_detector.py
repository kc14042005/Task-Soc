import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score
import joblib
import os
import json

class BruteForceDetector:
    """Feature engineering and classification for Brute Force detection"""
    
    def __init__(self, model_dir='brute_models'):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
        self.model = None
        
    def extract_features(self, df):
        """Engineer behavioral features from logs"""
        print("Engineering features...")
        df = df.sort_values('timestamp')
        
        # Group by IP and 1-minute window
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df_grouped = df.set_index('timestamp').groupby([pd.Grouper(freq='1min'), 'source_ip'])
        
        features = df_grouped.agg(
            attempts=('status', 'count'),
            failed_count=('status', lambda x: (x == 'failed').sum()),
            success_count=('status', lambda x: (x == 'success').sum()),
            unique_users=('username', 'nunique')
        ).reset_index()
        
        # Calculate Ratios
        features['failed_ratio'] = features['failed_count'] / features['attempts']
        features['attempts_per_sec'] = features['attempts'] / 60
        
        # Map labels back (if any log in that window was an attack, the window is an attack)
        labels = df_grouped['label'].max().reset_index()
        features['label'] = labels['label']
        
        return features

    def train(self, features):
        print("Training Brute Force Classifier...")
        X = features[['attempts', 'failed_count', 'success_count', 'unique_users', 'failed_ratio', 'attempts_per_sec']]
        y = features['label']
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        model = XGBClassifier(random_state=42)
        model.fit(X_train, y_train)
        
        # Eval
        y_pred = model.predict(X_test)
        print("\nEvaluation:")
        print(classification_report(y_test, y_pred))
        
        self.model = model
        joblib.dump(model, os.path.join(self.model_dir, 'brute_model.pkl'))
        return f1_score(y_test, y_pred)

    def predict(self, df):
        """Predict attacks on new data"""
        if self.model is None:
            self.model = joblib.load(os.path.join(self.model_dir, 'brute_model.pkl'))
            
        features = self.extract_features(df)
        X = features[['attempts', 'failed_count', 'success_count', 'unique_users', 'failed_ratio', 'attempts_per_sec']]
        
        probs = self.model.predict_proba(X)[:, 1]
        features['confidence'] = probs
        features['prediction'] = (probs > 0.5).astype(int)
        
        alerts = features[features['prediction'] == 1].copy()
        return alerts
