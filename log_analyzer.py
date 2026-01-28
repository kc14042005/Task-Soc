#!/usr/bin/env python3
import argparse
import sys
from log_detector import LogAnomalyDetector
from log_dataset import LogDataset
import pandas as pd

class LogAnalyzer:
    """CLI tool for log anomaly detection"""
    
    def __init__(self):
        self.detector = LogAnomalyDetector()
        if not self.detector.load_model():
            print("ERROR: Model not found. Run: python log_train.py")
            sys.exit(1)
        print(f"✓ Loaded: {self.detector.best_model_name}\n")
    
    def analyze_logs(self, log_file=None, top_n=20):
        """Analyze logs and detect anomalies"""
        print("="*60)
        print("LOG ANOMALY ANALYZER")
        print("="*60)
        
        # Load logs
        if log_file:
            df = pd.read_csv(log_file)
            print(f"Loaded: {log_file}")
        else:
            dataset = LogDataset()
            df = dataset.load_dataset()
        
        print(f"Total logs: {len(df)}")
        print("-" * 60)
        
        # Prepare data
        X_scaled, y, df_processed = self.detector.prepare_data(df)
        
        # Detect anomalies
        print("Detecting anomalies...")
        anomalies = self.detector.detect_anomalies(df_processed, X_scaled)
        
        print(f"\n✓ Found {len(anomalies)} anomalies")
        
        # Display results
        print("\n" + "="*60)
        print(f"TOP {top_n} ANOMALIES")
        print("="*60)
        
        top_anomalies = anomalies.head(top_n)
        for i, (idx, row) in enumerate(top_anomalies.iterrows(), 1):
            print(f"\n[{i}] {row['timestamp']}")
            print(f"    User: {row['user']}")
            print(f"    IP: {row['source_ip']}")
            print(f"    Action: {row['action']}")
            print(f"    Status: {row['status']}")
            print(f"    ⚠️  Reason: {row['reason']}")
        
        print("\n" + "="*60)
        
        return anomalies

def main():
    parser = argparse.ArgumentParser(
        description='Log Anomaly Analyzer - Detect suspicious security events',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python log_analyzer.py
  python log_analyzer.py --top 10
  python log_analyzer.py --file custom_logs.csv
        """
    )
    
    parser.add_argument('--file', help='Path to log CSV file')
    parser.add_argument('--top', type=int, default=20, help='Number of top anomalies to show')
    parser.add_argument('--export', help='Export anomalies to CSV file')
    
    args = parser.parse_args()
    
    analyzer = LogAnalyzer()
    anomalies = analyzer.analyze_logs(args.file, args.top)
    
    if args.export:
        anomalies[['timestamp', 'user', 'source_ip', 'action', 'status', 'reason']].to_csv(
            args.export, index=False
        )
        print(f"\n✓ Exported to: {args.export}")

if __name__ == "__main__":
    main()
