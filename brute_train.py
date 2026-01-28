from brute_dataset import BruteForceDataset
from brute_detector import BruteForceDetector
import pandas as pd
import sys

def main():
    print("="*60)
    print("BRUTE FORCE ATTACK DETECTOR")
    print("="*60)
    
    # 1. Dataset
    ds = BruteForceDataset()
    df = ds.load_data()
    
    # 2. Train
    detector = BruteForceDetector()
    features = detector.extract_features(df)
    detector.train(features)
    
    # 3. Detect (Run on same data for demonstration)
    print("\n[!] Running detection on logs...")
    alerts = detector.predict(df)
    
    if not alerts.empty:
        print(f"\n🚨 FOUND {len(alerts)} ATTACK WINDOWS")
        print("-" * 60)
        # Show top alerts
        display = alerts[['timestamp', 'source_ip', 'attempts', 'unique_users', 'confidence']].head(10)
        for _, row in display.iterrows():
            print(f"TIME: {row['timestamp']} | IP: {row['source_ip']} | ATTEMPTS: {row['attempts']} | CONFIDENCE: {row['confidence']:.4f}")
        
        alerts.to_csv('brute_alerts.csv', index=False)
        print(f"\n✓ Full alerts saved to: brute_alerts.csv")
    else:
        print("\n✅ No brute force attacks detected.")

if __name__ == "__main__":
    main()
