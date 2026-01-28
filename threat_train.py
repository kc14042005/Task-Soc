from threat_dataset import ThreatDataset
from threat_classifier import ThreatClassifier
import json
import os

def main():
    print("\n" + "="*60)
    print("THREAT INTELLIGENCE CLASSIFIER - TRAINING")
    print("="*60)
    
    # Load dataset
    print("\n[STEP 1/3] Loading Dataset")
    print("-" * 60)
    dataset = ThreatDataset()
    df = dataset.load_dataset()
    
    # Train
    print("\n[STEP 2/3] Training")
    print("-" * 60)
    classifier = ThreatClassifier()
    X_train, X_test, y_train, y_test = classifier.prepare_data(df)
    classifier.train_models(X_train, y_train)
    
    # Evaluate
    print("\n[STEP 3/3] Evaluation")
    print("-" * 60)
    results = classifier.evaluate_models(X_test, y_test)
    
    # Save results
    os.makedirs('threat_reports', exist_ok=True)
    with open('threat_reports/evaluation.json', 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n✓ Results: threat_reports/evaluation.json")
    
    # Save models
    print("\n" + "="*60)
    print("Saving Models")
    print("="*60)
    classifier.save_models()
    
    print("\n" + "="*60)
    print("TRAINING COMPLETE!")
    print("="*60)
    print(f"\nBest: {classifier.best_model_name}")
    print("Categories:", ', '.join(classifier.categories))

if __name__ == "__main__":
    main()
