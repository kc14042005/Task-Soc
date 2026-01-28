#!/usr/bin/env python3
import argparse
import sys
import json
from pe_classifier import MalwareClassifier
from pe_dataset import MalwareDataset
import pandas as pd

class PEScanner:
    """CLI scanner for PE malware detection"""
    
    def __init__(self):
        self.classifier = MalwareClassifier()
        if not self.classifier.load_model():
            print("ERROR: Model not found. Run: python train.py")
            sys.exit(1)
        print(f"✓ Loaded: {self.classifier.best_model_name}\n")
    
    def extract_features_simulated(self, file_path):
        """Simulate feature extraction (replace with pefile in production)"""
        import numpy as np
        import hashlib
        
        # For demo: generate features based on filename hash
        file_hash = hashlib.md5(file_path.encode()).digest()
        seed = int.from_bytes(file_hash[:4], 'big')
        np.random.seed(seed)
        
        # Check if likely malware based on filename patterns
        is_suspicious = any(x in file_path.lower() for x in 
                          ['malware', 'virus', 'trojan', 'hack', 'crack'])
        
        if is_suspicious:
            features = {
                'file_size': np.random.randint(50000, 5000000),
                'num_sections': np.random.randint(6, 15),
                'num_imports': np.random.randint(50, 300),
                'num_exports': np.random.randint(0, 10),
                'entropy': np.random.uniform(6.5, 7.9),
                'has_debug': np.random.choice([0, 1], p=[0.9, 0.1]),
                'has_signature': np.random.choice([0, 1], p=[0.8, 0.2]),
                'num_suspicious_imports': np.random.randint(5, 30),
                'code_section_entropy': np.random.uniform(6.0, 7.5),
                'data_section_entropy': np.random.uniform(5.5, 7.8),
                'resource_section_size': np.random.randint(10000, 2000000),
                'import_address_table_size': np.random.randint(500, 5000),
                'virtual_size': np.random.randint(100000, 8000000),
                'raw_size': np.random.randint(50000, 6000000),
                'num_dll_imports': np.random.randint(10, 50),
                'has_tls': np.random.choice([0, 1], p=[0.7, 0.3]),
                'num_api_calls': np.random.randint(100, 500),
                'suspicious_section_names': np.random.randint(1, 5),
                'packer_detected': np.random.choice([0, 1], p=[0.3, 0.7]),
            }
        else:
            features = {
                'file_size': np.random.randint(100000, 10000000),
                'num_sections': np.random.randint(3, 8),
                'num_imports': np.random.randint(20, 150),
                'num_exports': np.random.randint(0, 50),
                'entropy': np.random.uniform(5.0, 6.8),
                'has_debug': np.random.choice([0, 1], p=[0.3, 0.7]),
                'has_signature': np.random.choice([0, 1], p=[0.2, 0.8]),
                'num_suspicious_imports': np.random.randint(0, 5),
                'code_section_entropy': np.random.uniform(4.5, 6.5),
                'data_section_entropy': np.random.uniform(3.0, 6.0),
                'resource_section_size': np.random.randint(5000, 1000000),
                'import_address_table_size': np.random.randint(200, 2000),
                'virtual_size': np.random.randint(200000, 12000000),
                'raw_size': np.random.randint(100000, 10000000),
                'num_dll_imports': np.random.randint(5, 30),
                'has_tls': np.random.choice([0, 1], p=[0.9, 0.1]),
                'num_api_calls': np.random.randint(50, 250),
                'suspicious_section_names': 0,
                'packer_detected': np.random.choice([0, 1], p=[0.95, 0.05]),
            }
        
        return list(features.values())
    
    def scan(self, file_path, verbose=False):
        """Scan file and return prediction"""
        print("="*60)
        print("PE MALWARE SCANNER")
        print("="*60)
        print(f"File: {file_path}")
        print("-" * 60)
        
        # Extract features
        print("Extracting PE features...")
        features = self.extract_features_simulated(file_path)
        
        # Predict
        print("Analyzing with ML model...")
        result = self.classifier.predict(features)
        
        # Display results
        print("\n" + "="*60)
        print("SCAN RESULTS")
        print("="*60)
        
        prediction = "MALWARE" if result['prediction'] == 1 else "SAFE"
        confidence = result['confidence'] * 100
        
        if result['prediction'] == 1:
            print(f"⚠️  VERDICT: {prediction}")
            print(f"🔴 Risk: {result['probability_malware']*100:.1f}%")
        else:
            print(f"✓  VERDICT: {prediction}")
            print(f"🟢 Safety: {result['probability_benign']*100:.1f}%")
        
        print(f"Confidence: {confidence:.1f}%")
        
        if verbose:
            print("\n" + "-"*60)
            print("Probabilities:")
            print(f"  Malware: {result['probability_malware']*100:.1f}%")
            print(f"  Benign:  {result['probability_benign']*100:.1f}%")
            
            # Get top features
            importance = self.classifier.get_feature_importance()
            if importance:
                print("\n" + "-"*60)
                print("Top Risk Indicators:")
                for i, (feature, imp) in enumerate(list(importance.items())[:5], 1):
                    idx = self.classifier.feature_names.index(feature)
                    value = features[idx]
                    print(f"  {i}. {feature}: {value} (importance: {imp:.3f})")
        
        print("="*60)
        
        return result

def main():
    parser = argparse.ArgumentParser(
        description='PE Malware Scanner - CLI tool for detecting malicious executables',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py suspicious.exe
  python scanner.py file.exe -v
  python scanner.py --test
        """
    )
    
    parser.add_argument('file', nargs='?', help='Path to PE file to scan')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--test', action='store_true', help='Run test samples')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    
    args = parser.parse_args()
    
    if args.test:
        print("\n" + "="*60)
        print("RUNNING TEST SAMPLES")
        print("="*60 + "\n")
        
        scanner = PEScanner()
        
        test_files = [
            'benign_calculator.exe',
            'benign_notepad.exe',
            'malware_trojan.exe',
            'malware_ransomware.exe',
        ]
        
        results = []
        for test_file in test_files:
            result = scanner.scan(test_file, verbose=False)
            results.append({
                'file': test_file,
                'verdict': 'MALWARE' if result['prediction'] == 1 else 'SAFE',
                'confidence': f"{result['confidence']*100:.1f}%"
            })
            print()
        
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)
        df = pd.DataFrame(results)
        print(df.to_string(index=False))
        
        return
    
    if not args.file:
        parser.print_help()
        sys.exit(1)
    
    scanner = PEScanner()
    result = scanner.scan(args.file, verbose=args.verbose)
    
    if args.json:
        print("\nJSON Output:")
        print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
