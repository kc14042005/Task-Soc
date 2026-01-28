from pe_dataset import MalwareDataset
from pe_classifier import MalwareClassifier
import json
import os

def main():
    print("\n" + "="*60)
    print("PE MALWARE CLASSIFIER - TRAINING PIPELINE")
    print("="*60)
    
    # Load dataset
    print("\n[STEP 1/3] Loading Dataset")
    print("-" * 60)
    dataset = MalwareDataset()
    df = dataset.load_dataset()
    
    # Train models
    print("\n[STEP 2/3] Training Models")
    print("-" * 60)
    classifier = MalwareClassifier()
    X_train, X_test, y_train, y_test = classifier.prepare_data(df)
    classifier.train_models(X_train, y_train)
    
    # Evaluate
    print("\n[STEP 3/3] Evaluation")
    print("-" * 60)
    results = classifier.evaluate_models(X_test, y_test)
    
    # Save results
    os.makedirs('pe_reports', exist_ok=True)
    with open('pe_reports/evaluation.json', 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n✓ Results: pe_reports/evaluation.json")
    
    # Feature importance
    importance = classifier.get_feature_importance()
    if importance:
        with open('pe_reports/feature_importance.json', 'w') as f:
            json.dump(importance, f, indent=2)
        
        print("\nTop 15 Features:")
        print("-" * 60)
        for i, (feature, imp) in enumerate(list(importance.items())[:15], 1):
            print(f"{i:2d}. {feature:30s} {imp:.4f}")
    
    # Save models
    print("\n" + "="*60)
    print("Saving Models")
    print("="*60)
    classifier.save_models()
    
    print("\n" + "="*60)
    print("TRAINING COMPLETE!")
    print("="*60)
    print(f"\nBest: {classifier.best_model_name}")
    print("Run: python scanner.py <file>")

if __name__ == "__main__":
    main()
