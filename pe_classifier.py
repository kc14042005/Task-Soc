import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from lightgbm import LGBMClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                            f1_score, confusion_matrix, classification_report,
                            roc_auc_score, roc_curve)
from sklearn.preprocessing import StandardScaler
import joblib
import json
import os

class MalwareClassifier:
    """Train ML models for PE malware classification"""
    
    def __init__(self, model_dir='pe_models'):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
        self.models = {}
        self.scaler = StandardScaler()
        self.best_model = None
        self.best_model_name = None
        self.feature_names = None
    
    def prepare_data(self, df, test_size=0.25, random_state=42):
        """Prepare data for training"""
        print("\nPreparing data...")
        
        # Separate features and labels
        X = df.drop(['file_name', 'label'], axis=1)
        y = df['label']
        self.feature_names = X.columns.tolist()
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        print(f"✓ Training: {len(X_train)} samples")
        print(f"✓ Test: {len(X_test)} samples")
        print(f"✓ Features: {len(self.feature_names)}")
        
        return X_train_scaled, X_test_scaled, y_train, y_test
    
    def train_models(self, X_train, y_train):
        """Train classification models"""
        print("\n" + "="*60)
        print("Training Malware Classification Models")
        print("="*60)
        
        # Random Forest
        print("\n1. Training Random Forest...")
        rf = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1
        )
        rf.fit(X_train, y_train)
        self.models['Random Forest'] = rf
        print("   ✓ Trained")
        
        # LightGBM
        print("\n2. Training LightGBM...")
        lgbm = LGBMClassifier(
            n_estimators=100,
            max_depth=15,
            learning_rate=0.1,
            random_state=42,
            verbose=-1
        )
        lgbm.fit(X_train, y_train)
        self.models['LightGBM'] = lgbm
        print("   ✓ Trained")
        
        print("\n" + "="*60)
        print("All models trained!")
        print("="*60)
    
    def evaluate_models(self, X_test, y_test):
        """Evaluate trained models"""
        results = {}
        best_f1 = 0
        
        print("\n" + "="*60)
        print("Model Evaluation")
        print("="*60)
        
        for name, model in self.models.items():
            print(f"\n{name}:")
            print("-" * 40)
            
            # Predictions
            y_pred = model.predict(X_test)
            y_pred_proba = model.predict_proba(X_test)[:, 1]
            
            # Metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred)
            recall = recall_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred)
            roc_auc = roc_auc_score(y_test, y_pred_proba)
            
            results[name] = {
                'accuracy': float(accuracy),
                'precision': float(precision),
                'recall': float(recall),
                'f1_score': float(f1),
                'roc_auc': float(roc_auc),
                'confusion_matrix': confusion_matrix(y_test, y_pred).tolist()
            }
            
            print(f"Accuracy:  {accuracy:.4f}")
            print(f"Precision: {precision:.4f}")
            print(f"Recall:    {recall:.4f}")
            print(f"F1-Score:  {f1:.4f}")
            print(f"ROC-AUC:   {roc_auc:.4f}")
            
            if f1 > best_f1:
                best_f1 = f1
                self.best_model = model
                self.best_model_name = name
        
        print("\n" + "="*60)
        print(f"Best: {self.best_model_name} (F1: {best_f1:.4f})")
        print("="*60)
        
        return results
    
    def get_feature_importance(self, top_n=15):
        """Get feature importance"""
        if self.best_model is None:
            return None
        
        importance = self.best_model.feature_importances_
        feature_importance = {
            feature: float(imp)
            for feature, imp in zip(self.feature_names, importance)
        }
        
        # Sort by importance
        feature_importance = dict(sorted(
            feature_importance.items(),
            key=lambda x: x[1],
            reverse=True
        ))
        
        return feature_importance
    
    def save_models(self):
        """Save models"""
        print("\nSaving models...")
        
        # Save scaler
        scaler_path = os.path.join(self.model_dir, 'scaler.pkl')
        joblib.dump(self.scaler, scaler_path)
        print(f"✓ Scaler: {scaler_path}")
        
        # Save models
        for name, model in self.models.items():
            filename = name.lower().replace(' ', '_') + '.pkl'
            path = os.path.join(self.model_dir, filename)
            joblib.dump(model, path)
            print(f"✓ {name}: {path}")
        
        # Save best model
        if self.best_model:
            best_path = os.path.join(self.model_dir, 'best_model.pkl')
            joblib.dump(self.best_model, best_path)
            print(f"✓ Best model: {best_path}")
        
        # Save metadata
        metadata = {
            'best_model_name': self.best_model_name,
            'feature_names': self.feature_names
        }
        metadata_path = os.path.join(self.model_dir, 'metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        print(f"✓ Metadata: {metadata_path}")
    
    def load_model(self):
        """Load trained model"""
        try:
            best_path = os.path.join(self.model_dir, 'best_model.pkl')
            scaler_path = os.path.join(self.model_dir, 'scaler.pkl')
            metadata_path = os.path.join(self.model_dir, 'metadata.json')
            
            self.best_model = joblib.load(best_path)
            self.scaler = joblib.load(scaler_path)
            
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
                self.best_model_name = metadata['best_model_name']
                self.feature_names = metadata['feature_names']
            
            return True
        except Exception as e:
            print(f"Error: {e}")
            return False
    
    def predict(self, features):
        """Predict single sample"""
        if self.best_model is None:
            raise Exception("Model not loaded")
        
        # Scale
        features_scaled = self.scaler.transform([features])
        
        # Predict
        prediction = self.best_model.predict(features_scaled)[0]
        probability = self.best_model.predict_proba(features_scaled)[0]
        
        return {
            'prediction': int(prediction),
            'probability_malware': float(probability[1]),
            'probability_benign': float(probability[0]),
            'confidence': float(max(probability))
        }
