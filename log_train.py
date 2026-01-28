from log_dataset import LogDataset
from log_detector import LogAnomalyDetector
import json
import os

def main():
    print("\n" + "="*60)
    print("LOG ANOMALY DETECTOR - TRAINING PIPELINE")
    print("="*60)
    
    # Load dataset
    print("\n[STEP 1/3] Loading Dataset")
    print("-" * 60)
    dataset = LogDataset()
    df = dataset.load_dataset()
    
    # Train
    print("\n[STEP 2/3] Training")
    print("-" * 60)
    detector = LogAnomalyDetector()
    X_scaled, y, df_processed = detector.prepare_data(df)
    detector.train_models(X_scaled)
    
    # Evaluate
    print("\n[STEP 3/3] Evaluation")
    print("-" * 60)
    results = detector.evaluate_models(X_scaled, y)
    
    # Save results
    os.makedirs('log_reports', exist_ok=True)
    with open('log_reports/evaluation.json', 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n✓ Results: log_reports/evaluation.json")
    
    # Detect and analyze anomalies
    print("\n" + "="*60)
    print("Detecting Anomalies")
    print("="*60)
    anomalies = detector.detect_anomalies(df_processed, X_scaled)
    
    print(f"\nTop 10 Anomalies:")
    print("-" * 60)
    top_anomalies = anomalies.head(10)
    for idx, row in top_anomalies.iterrows():
        print(f"\n{idx+1}. {row['timestamp']}")
        print(f"   User: {row['user']} | IP: {row['source_ip']}")
        print(f"   Action: {row['action']} | Status: {row['status']}")
        print(f"   Reason: {row['reason']}")
    
    # Save anomalies
    anomalies_path = 'log_reports/detected_anomalies.csv'
    anomalies[['timestamp', 'user', 'source_ip', 'action', 'status', 'reason']].to_csv(
        anomalies_path, index=False
    )
    print(f"\n✓ Anomalies saved: {anomalies_path}")
    
    # Save models
    print("\n" + "="*60)
    print("Saving Models")
    print("="*60)
    detector.save_models()
    
    print("\n" + "="*60)
    print("TRAINING COMPLETE!")
    print("="*60)
    print(f"\nBest: {detector.best_model_name}")
    print("Run: python log_analyzer.py")

if __name__ == "__main__":
    main()
