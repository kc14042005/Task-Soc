import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, accuracy_score, f1_score
from sklearn.preprocessing import StandardScaler
import joblib
import json
import os
from phishing_dataset import PhishingDataset, PhishingFeatureExtractor

class PhishingTrainer:
    """Train and evaluate phishing detection models"""
    
    def __init__(self, model_dir='phishing_models'):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
        self.models = {}
        self.scaler = StandardScaler()
        self.best_model = None
        self.best_model_name = None
        self.extractor = PhishingFeatureExtractor()
        
    def prepare_data(self, df):
        """Split and scale data"""
        feature_cols = self.extractor.get_feature_names()
        X = df[feature_cols]
        y = df['label']
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        return X_train_scaled, X_test_scaled, y_train, y_test

    def train_all(self, X_train, y_train):
        """Train multiple models"""
        print("\nTraining models...")
        
        # 1. Random Forest
        rf = RandomForestClassifier(n_estimators=100, random_state=42)
        rf.fit(X_train, y_train)
        self.models['Random Forest'] = rf
        print("✓ Random Forest trained")
        
        # 2. Logistic Regression
        lr = LogisticRegression(random_state=42)
        lr.fit(X_train, y_train)
        self.models['Logistic Regression'] = lr
        print("✓ Logistic Regression trained")
        
        # 3. XGBoost
        xgb = XGBClassifier(use_label_encoder=False, eval_metric='logloss', random_state=42)
        xgb.fit(X_train, y_train)
        self.models['XGBoost'] = xgb
        print("✓ XGBoost trained")

    def evaluate(self, X_test, y_test):
        """Evaluate models and pick best one"""
        results = {}
        best_score = 0
        
        print("\nEvaluation Results:")
        print("-" * 30)
        
        for name, model in self.models.items():
            y_pred = model.predict(X_test)
            acc = accuracy_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred)
            
            results[name] = {
                'accuracy': float(acc),
                'f1_score': float(f1)
            }
            print(f"{name}: Accuracy={acc:.4f}, F1={f1:.4f}")
            
            if f1 > best_score:
                best_score = f1
                self.best_model = model
                self.best_model_name = name
                
        print("-" * 30)
        print(f"Best Model: {self.best_model_name}")
        return results

    def save_assets(self):
        """Save best model, scaler, and results"""
        if self.best_model is None:
            return
            
        # Save model
        model_path = os.path.join(self.model_dir, 'best_model.pkl')
        joblib.dump(self.best_model, model_path)
        
        # Save scaler
        scaler_path = os.path.join(self.model_dir, 'scaler.pkl')
        joblib.dump(self.scaler, scaler_path)
        
        # Save metadata
        metadata = {
            'best_model_name': self.best_model_name,
            'features': self.extractor.get_feature_names()
        }
        with open(os.path.join(self.model_dir, 'metadata.json'), 'w') as f:
            json.dump(metadata, f, indent=2)
            
        print(f"\n✓ Saved model and scaler to {self.model_dir}/")

def main():
    print("="*60)
    print("PHISHING URL DETECTOR - TRAINING PIPELINE")
    print("="*60)
    
    # 1. Load data
    dataset = PhishingDataset()
    df = dataset.load_dataset()
    
    # 2. Train
    trainer = PhishingTrainer()
    X_train, X_test, y_train, y_test = trainer.prepare_data(df)
    trainer.train_all(X_train, y_train)
    
    # 3. Evaluate
    results = trainer.evaluate(X_test, y_test)
    
    # 4. Save
    trainer.save_assets()
    
    # Save results to report dir
    os.makedirs('phishing_reports', exist_ok=True)
    with open('phishing_reports/evaluation.json', 'w') as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
