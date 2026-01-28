import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, f1_score
import joblib
import json
import os
import re

class ThreatClassifier:
    """Classify threat intelligence reports"""
    
    def __init__(self, model_dir='threat_models'):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
        self.models = {}
        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 3),
            stop_words='english',
            min_df=1
        )
        self.best_model = None
        self.best_model_name = None
        self.categories = None
    
    def preprocess_text(self, text):
        """Clean and preprocess text"""
        # Lowercase
        text = text.lower()
        # Remove special characters but keep spaces
        text = re.sub(r'[^a-z0-9\s]', '', text)
        # Remove extra spaces
        text = ' '.join(text.split())
        return text
    
    def prepare_data(self, df, test_size=0.25, random_state=42):
        """Prepare text data"""
        print("\nPreparing data...")
        
        # Preprocess
        df['text_clean'] = df['text'].apply(self.preprocess_text)
        
        X = df['text_clean'].values
        y = df['category'].values
        self.categories = sorted(df['category'].unique())
        
        # Split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        # Vectorize
        print("Vectorizing text...")
        X_train_vec = self.vectorizer.fit_transform(X_train)
        X_test_vec = self.vectorizer.transform(X_test)
        
        print(f"✓ Training: {len(X_train)} samples")
        print(f"✓ Test: {len(X_test)} samples")
        print(f"✓ Features: {X_train_vec.shape[1]}")
        print(f"✓ Categories: {len(self.categories)}")
        
        return X_train_vec, X_test_vec, y_train, y_test
    
    def train_models(self, X_train, y_train):
        """Train classification models"""
        print("\n" + "="*60)
        print("Training Threat Classification Models")
        print("="*60)
        
        # Logistic Regression
        print("\n1. Training Logistic Regression...")
        lr = LogisticRegression(max_iter=1000, random_state=42)
        lr.fit(X_train, y_train)
        self.models['Logistic Regression'] = lr
        print("   ✓ Trained")
        
        # Linear SVM
        print("\n2. Training Linear SVM...")
        svm = LinearSVC(max_iter=2000, random_state=42)
        svm.fit(X_train, y_train)
        self.models['Linear SVM'] = svm
        print("   ✓ Trained")
        
        # Random Forest
        print("\n3. Training Random Forest...")
        rf = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42, n_jobs=-1)
        rf.fit(X_train, y_train)
        self.models['Random Forest'] = rf
        print("   ✓ Trained")
        
        print("\n" + "="*60)
        print("Models trained!")
        print("="*60)
    
    def evaluate_models(self, X_test, y_test):
        """Evaluate models"""
        results = {}
        best_f1 = 0
        
        print("\n" + "="*60)
        print("Evaluation")
        print("="*60)
        
        for name, model in self.models.items():
            print(f"\n{name}:")
            print("-" * 40)
            
            y_pred = model.predict(X_test)
            
            accuracy = accuracy_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred, average='weighted')
            
            results[name] = {
                'accuracy': float(accuracy),
                'f1_score': float(f1)
            }
            
            print(f"Accuracy: {accuracy:.4f}")
            print(f"F1-Score: {f1:.4f}")
            
            if f1 > best_f1:
                best_f1 = f1
                self.best_model = model
                self.best_model_name = name
        
        print("\n" + "="*60)
        print(f"Best: {self.best_model_name} (F1: {best_f1:.4f})")
        print("="*60)
        
        return results
    
    def extract_key_terms(self, text, top_n=5):
        """Extract key terms from text"""
        # Vectorize text
        text_vec = self.vectorizer.transform([self.preprocess_text(text)])
        
        # Get feature names and scores
        feature_names = self.vectorizer.get_feature_names_out()
        scores = text_vec.toarray()[0]
        
        # Get top terms
        top_indices = np.argsort(scores)[-top_n:][::-1]
        key_terms = [feature_names[i] for i in top_indices if scores[i] > 0]
        
        return key_terms
    
    def predict(self, text):
        """Predict category for text"""
        if self.best_model is None:
            raise Exception("Model not loaded")
        
        # Preprocess and vectorize
        text_clean = self.preprocess_text(text)
        text_vec = self.vectorizer.transform([text_clean])
        
        # Predict
        prediction = self.best_model.predict(text_vec)[0]
        
        # Get probabilities if available
        if hasattr(self.best_model, 'predict_proba'):
            probabilities = self.best_model.predict_proba(text_vec)[0]
            prob_dict = {cat: float(prob) for cat, prob in zip(self.categories, probabilities)}
        elif hasattr(self.best_model, 'decision_function'):
            scores = self.best_model.decision_function(text_vec)[0]
            exp_scores = np.exp(scores - np.max(scores))
            probabilities = exp_scores / exp_scores.sum()
            prob_dict = {cat: float(prob) for cat, prob in zip(self.categories, probabilities)}
        else:
            prob_dict = {cat: 1.0 if cat == prediction else 0.0 for cat in self.categories}
        
        # Extract key terms
        key_terms = self.extract_key_terms(text)
        
        return {
            'category': prediction,
            'probabilities': prob_dict,
            'confidence': max(prob_dict.values()),
            'key_terms': key_terms
        }
    
    def save_models(self):
        """Save models"""
        print("\nSaving models...")
        
        # Save vectorizer
        vec_path = os.path.join(self.model_dir, 'vectorizer.pkl')
        joblib.dump(self.vectorizer, vec_path)
        print(f"✓ Vectorizer: {vec_path}")
        
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
            print(f"✓ Best: {best_path}")
        
        # Save metadata
        metadata = {
            'best_model_name': self.best_model_name,
            'categories': self.categories
        }
        meta_path = os.path.join(self.model_dir, 'metadata.json')
        with open(meta_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        print(f"✓ Metadata: {meta_path}")
    
    def load_model(self):
        """Load model"""
        try:
            best_path = os.path.join(self.model_dir, 'best_model.pkl')
            vec_path = os.path.join(self.model_dir, 'vectorizer.pkl')
            meta_path = os.path.join(self.model_dir, 'metadata.json')
            
            self.best_model = joblib.load(best_path)
            self.vectorizer = joblib.load(vec_path)
            
            with open(meta_path, 'r') as f:
                metadata = json.load(f)
                self.best_model_name = metadata['best_model_name']
                self.categories = metadata['categories']
            
            return True
        except Exception as e:
            print(f"Error: {e}")
            return False
