import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score
from sklearn.preprocessing import LabelEncoder
import joblib
import os

class CVESeverityPredictor:
    """Predict CVE severity using TF-IDF and XGBoost"""
    
    def __init__(self, model_dir='cve_models'):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english', ngram_range=(1, 2))
        self.model = XGBClassifier(random_state=42)
        self.le_vector = LabelEncoder()
        self.le_complex = LabelEncoder()
        
    def prepare_features(self, df, training=False):
        """Vectorize text and encode categorical fields"""
        if training:
            text_features = self.vectorizer.fit_transform(df['description']).toarray()
            df['vector_enc'] = self.le_vector.fit_transform(df['attack_vector'])
            df['complex_enc'] = self.le_complex.fit_transform(df['complexity'])
        else:
            text_features = self.vectorizer.transform(df['description']).toarray()
            df['vector_enc'] = self.le_vector.transform(df['attack_vector'])
            df['complex_enc'] = self.le_complex.transform(df['complexity'])
            
        structured_features = df[['vector_enc', 'complex_enc']].values
        return np.hstack([text_features, structured_features])

    def train(self, df):
        print("Training CVE Severity Model...")
        X = self.prepare_features(df, training=True)
        y = df['label']
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        self.model.fit(X_train, y_train)
        
        y_pred = self.model.predict(X_test)
        print("\nModel Evaluation Report:")
        print(classification_report(y_test, y_pred, target_names=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']))
        
        # Save assets
        joblib.dump(self.model, os.path.join(self.model_dir, 'cve_model.pkl'))
        joblib.dump(self.vectorizer, os.path.join(self.model_dir, 'vectorizer.pkl'))
        joblib.dump(self.le_vector, os.path.join(self.model_dir, 'le_vector.pkl'))
        joblib.dump(self.le_complex, os.path.join(self.model_dir, 'le_complex.pkl'))
        
        return f1_score(y_test, y_pred, average='weighted')

    def predict(self, text, vector='NETWORK', complexity='LOW'):
        """Predict severity for a new CVE description"""
        if self.model is None or not hasattr(self.vectorizer, 'fixed_vocabulary_'):
            self.model = joblib.load(os.path.join(self.model_dir, 'cve_model.pkl'))
            self.vectorizer = joblib.load(os.path.join(self.model_dir, 'vectorizer.pkl'))
            self.le_vector = joblib.load(os.path.join(self.model_dir, 'le_vector.pkl'))
            self.le_complex = joblib.load(os.path.join(self.model_dir, 'le_complex.pkl'))
            
        test_df = pd.DataFrame([{
            'description': text,
            'attack_vector': vector,
            'complexity': complexity
        }])
        
        X = self.prepare_features(test_df)
        probs = self.model.predict_proba(X)[0]
        pred_idx = np.argmax(probs)
        
        sev_map = {0: 'LOW', 1: 'MEDIUM', 2: 'HIGH', 3: 'CRITICAL'}
        
        # Extract top keywords from TF-IDF
        feature_names = self.vectorizer.get_feature_names_out()
        tfidf_scores = self.vectorizer.transform([text]).toarray()[0]
        top_indices = tfidf_scores.argsort()[-3:][::-1]
        keywords = [feature_names[i] for i in top_indices if tfidf_scores[i] > 0]
        
        return {
            'severity': sev_map[pred_idx],
            'confidence': float(probs[pred_idx]),
            'top_keywords': keywords
        }
