import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support
import joblib
import json
import os
from datetime import datetime

class LogAnomalyDetector:
    """Anomaly detection for security logs"""
    
    def __init__(self, model_dir='log_models'):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
        self.models = {}
        self.scaler = StandardScaler()
        self.encoders = {}
        self.best_model = None
        self.best_model_name = None
        self.feature_names = None
    
    def prepare_data(self, df):
        """Prepare log data for training"""
        print("\nPreparing data...")
        
        # Parse timestamp features
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
        df['is_night'] = df['hour'].isin(range(0, 6)).astype(int)
        
        # Encode categorical features
        categorical_cols = ['user', 'source_ip', 'action', 'status']
        for col in categorical_cols:
            le = LabelEncoder()
            df[f'{col}_encoded'] = le.fit_transform(df[col].astype(str))
            self.encoders[col] = le
        
        # Select features for training
        feature_cols = [
            'hour', 'day_of_week', 'is_weekend', 'is_night',
            'user_encoded', 'source_ip_encoded', 'action_encoded', 'status_encoded',
            'session_duration', 'bytes_transferred', 'failed_attempts', 'privilege_level'
        ]
        
        X = df[feature_cols]
        y = df['is_anomaly']
        self.feature_names = feature_cols
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        print(f"✓ Features: {len(feature_cols)}")
        print(f"✓ Samples: {len(X)}")
        print(f"✓ Anomalies: {sum(y)}")
        
        return X_scaled, y, df
    
    def train_models(self, X_train):
        """Train anomaly detection models"""
        print("\n" + "="*60)
        print("Training Anomaly Detection Models")
        print("="*60)
        
        # Isolation Forest
        print("\n1. Training Isolation Forest...")
        iso_forest = IsolationForest(
            contamination=0.2,
            random_state=42,
            n_estimators=100
        )
        iso_forest.fit(X_train)
        self.models['Isolation Forest'] = iso_forest
        print("   ✓ Trained")
        
        # One-Class SVM
        print("\n2. Training One-Class SVM...")
        oc_svm = OneClassSVM(
            kernel='rbf',
            gamma='auto',
            nu=0.2
        )
        oc_svm.fit(X_train)
        self.models['One-Class SVM'] = oc_svm
        print("   ✓ Trained")
        
        print("\n" + "="*60)
        print("Models trained!")
        print("="*60)
    
    def evaluate_models(self, X_test, y_test):
        """Evaluate anomaly detection models"""
        results = {}
        best_f1 = 0
        
        print("\n" + "="*60)
        print("Model Evaluation")
        print("="*60)
        
        for name, model in self.models.items():
            print(f"\n{name}:")
            print("-" * 40)
            
            # Predict (-1 for anomaly, 1 for normal)
            predictions = model.predict(X_test)
            # Convert to 0/1 (1 for anomaly)
            y_pred = (predictions == -1).astype(int)
            
            # Calculate metrics
            precision, recall, f1, _ = precision_recall_fscore_support(
                y_test, y_pred, average='binary', zero_division=0
            )
            
            accuracy = (y_pred == y_test).mean()
            cm = confusion_matrix(y_test, y_pred)
            
            results[name] = {
                'accuracy': float(accuracy),
                'precision': float(precision),
                'recall': float(recall),
                'f1_score': float(f1),
                'confusion_matrix': cm.tolist()
            }
            
            print(f"Accuracy:  {accuracy:.4f}")
            print(f"Precision: {precision:.4f}")
            print(f"Recall:    {recall:.4f}")
            print(f"F1-Score:  {f1:.4f}")
            
            if f1 > best_f1:
                best_f1 = f1
                self.best_model = model
                self.best_model_name = name
        
        print("\n" + "="*60)
        print(f"Best: {self.best_model_name} (F1: {best_f1:.4f})")
        print("="*60)
        
        return results
    
    def detect_anomalies(self, df, X_scaled):
        """Detect anomalies and provide explanations"""
        predictions = self.best_model.predict(X_scaled)
        anomaly_scores = self.best_model.score_samples(X_scaled) if hasattr(self.best_model, 'score_samples') else predictions
        
        df['anomaly_prediction'] = (predictions == -1).astype(int)
        df['anomaly_score'] = anomaly_scores
        
        # Get top anomalies
        anomalies = df[df['anomaly_prediction'] == 1].copy()
        anomalies = anomalies.sort_values('anomaly_score')
        
        # Generate reasons
        anomalies['reason'] = anomalies.apply(self._generate_reason, axis=1)
        
        return anomalies
    
    def _generate_reason(self, row):
        """Generate explanation for anomaly"""
        reasons = []
        
        if row['failed_attempts'] > 5:
            reasons.append(f"High failed login attempts ({row['failed_attempts']})")
        
        if row['bytes_transferred'] > 5000000:
            reasons.append(f"Large data transfer ({row['bytes_transferred']:,} bytes)")
        
        if row['is_night'] == 1:
            reasons.append("Access during unusual hours (night)")
        
        if row['privilege_level'] >= 3:
            reasons.append("High privilege access")
        
        if row['action'] in ['privilege_escalation', 'admin_access', 'config_change']:
            reasons.append(f"Sensitive action: {row['action']}")
        
        if row['status'] == 'failed':
            reasons.append("Failed operation")
        
        if not reasons:
            reasons.append("Statistical deviation from normal behavior")
        
        return "; ".join(reasons)
    
    def save_models(self):
        """Save models and encoders"""
        print("\nSaving models...")
        
        # Save scaler
        scaler_path = os.path.join(self.model_dir, 'scaler.pkl')
        joblib.dump(self.scaler, scaler_path)
        print(f"✓ Scaler: {scaler_path}")
        
        # Save encoders
        encoders_path = os.path.join(self.model_dir, 'encoders.pkl')
        joblib.dump(self.encoders, encoders_path)
        print(f"✓ Encoders: {encoders_path}")
        
        # Save models
        for name, model in self.models.items():
            filename = name.lower().replace(' ', '_').replace('-', '_') + '.pkl'
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
            encoders_path = os.path.join(self.model_dir, 'encoders.pkl')
            metadata_path = os.path.join(self.model_dir, 'metadata.json')
            
            self.best_model = joblib.load(best_path)
            self.scaler = joblib.load(scaler_path)
            self.encoders = joblib.load(encoders_path)
            
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
                self.best_model_name = metadata['best_model_name']
                self.feature_names = metadata['feature_names']
            
            return True
        except Exception as e:
            print(f"Error: {e}")
            return False
