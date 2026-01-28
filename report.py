import json
import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime

def generate_report():
    print("="*80)
    print("PE MALWARE CLASSIFIER - EVALUATION REPORT")
    print("="*80)
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)
    
    results_path = 'pe_reports/evaluation.json'
    if not os.path.exists(results_path):
        print("\nError: Run train.py first")
        return
    
    with open(results_path, 'r') as f:
        results = json.load(f)
    
    report_lines = []
    report_lines.append("\n" + "="*80)
    report_lines.append("EXECUTIVE SUMMARY")
    report_lines.append("="*80)
    
    summary = """
PE Malware Classifier uses machine learning to detect malicious Windows executables
by analyzing static PE (Portable Executable) header features. The system classifies
files as MALWARE or BENIGN (SAFE) based on structural characteristics.

KEY APPROACH:
- Static analysis of PE file features (no code execution)
- Machine learning models: Random Forest and LightGBM
- Feature extraction: PE headers, sections, imports, entropy
- Binary classification: MALWARE vs BENIGN
"""
    report_lines.append(summary)
    print(summary)
    
    # Model comparison
    report_lines.append("\n" + "="*80)
    report_lines.append("MODEL PERFORMANCE")
    report_lines.append("="*80)
    
    metrics_df = pd.DataFrame(results).T
    print("\n" + metrics_df.to_string())
    report_lines.append("\n" + metrics_df.to_string())
    
    # Confusion matrices
    report_lines.append("\n\n" + "="*80)
    report_lines.append("CONFUSION MATRICES")
    report_lines.append("="*80)
    
    for model_name, model_results in results.items():
        cm = model_results['confusion_matrix']
        report_lines.append(f"\n{model_name}:")
        report_lines.append("-" * 40)
        report_lines.append(f"True Negatives (Benign->Benign):  {cm[0][0]}")
        report_lines.append(f"False Positives (Benign->Malware): {cm[0][1]}")
        report_lines.append(f"False Negatives (Malware->Benign): {cm[1][0]}")
        report_lines.append(f"True Positives (Malware->Malware): {cm[1][1]}")
        
        print(f"\n{model_name}:")
        print("-" * 40)
        print(f"True Negatives:  {cm[0][0]}")
        print(f"False Positives: {cm[0][1]}")
        print(f"False Negatives: {cm[1][0]}")
        print(f"True Positives:  {cm[1][1]}")
    
    # Feature importance
    importance_path = 'pe_reports/feature_importance.json'
    if os.path.exists(importance_path):
        with open(importance_path, 'r') as f:
            importance = json.load(f)
        
        report_lines.append("\n\n" + "="*80)
        report_lines.append("TOP PREDICTIVE FEATURES")
        report_lines.append("="*80)
        
        print("\n" + "="*80)
        print("TOP PREDICTIVE FEATURES")
        print("="*80)
        
        for i, (feature, imp) in enumerate(list(importance.items())[:15], 1):
            line = f"{i:2d}. {feature:35s} {imp:.6f}"
            print(line)
            report_lines.append("\n" + line)
    
    # Detailed analysis
    report_lines.append("\n\n" + "="*80)
    report_lines.append("DETAILED ANALYSIS")
    report_lines.append("="*80)
    
    analysis = """

1. PE FEATURES ANALYZED
   ---------------------
   - File size and section sizes
   - Number of sections, imports, exports
   - File entropy (measure of randomness/packing)
   - Section-specific entropy (code, data)
   - Import Address Table characteristics
   - DLL import patterns
   - Suspicious import functions
   - Digital signature presence
   - Debug information
   - TLS (Thread Local Storage) usage
   - Packer detection indicators
   - Suspicious section names

2. METHODOLOGY
   ------------
   A. Static Analysis:
      - No code execution required
      - Fast scanning (<1 second per file)
      - Safe for unknown malware samples
   
   B. Feature Engineering:
      - 19 numerical features extracted
      - Normalized for ML processing
      - Based on known malware indicators
   
   C. Model Training:
      - Random Forest: Ensemble of decision trees
      - LightGBM: Gradient boosting framework
      - 75-25 train-test split
      - Balanced dataset (50% malware, 50% benign)

3. KEY MALWARE INDICATORS
   ------------------------
   HIGH ENTROPY:
   - Entropy >7.0 often indicates packing/encryption
   - Malware uses packers to evade detection
   
   SUSPICIOUS IMPORTS:
   - Registry manipulation functions
   - Process injection APIs
   - Anti-debugging functions
   - Network communication APIs
   
   SECTION CHARACTERISTICS:
   - Unusual section names (.hidden, .packed)
   - Mismatched virtual/raw sizes
   - Executable resource sections
   
   BEHAVIORAL FLAGS:
   - No digital signature
   - TLS callbacks (anti-debugging)
   - High import count (code obfuscation)

4. DEPLOYMENT CONSIDERATIONS
   ---------------------------
   A. Use Cases:
      - SOC initial triage
      - Email attachment scanning
      - Network gateway inspection
      - Endpoint protection
      - Malware analysis automation
   
   B. Limitations:
      - Static analysis only (no behavior monitoring)
      - Can miss polymorphic malware
      - Requires PE format (Windows executables)
      - May flag legitimate packers
   
   C. Best Practices:
      - Combine with dynamic analysis
      - Update model with new malware samples
      - Use in layered security approach
      - Human review for borderline cases

5. PERFORMANCE METRICS
   --------------------
   ACCURACY: Overall correctness
   PRECISION: Malware detections that are correct
   RECALL: Actual malware that was detected
   F1-SCORE: Balanced metric
   ROC-AUC: Model discrimination ability

6. FUTURE ENHANCEMENTS
   --------------------
   - Deep learning models (CNN on raw bytes)
   - Dynamic analysis integration
   - Behavioral heuristics
   - YARA rule integration
   - Real-time scanning API
   - Cloud-based threat intelligence
   - Multi-format support (ELF, Mach-O)

7. CONCLUSION
   -----------
   The PE Malware Classifier provides fast, accurate static analysis of Windows
   executables. With proper deployment and continuous updates, it serves as an
   effective first-line defense in malware detection pipelines.
"""
    
    report_lines.append(analysis)
    print(analysis)
    
    # Save report
    report_text = '\n'.join(report_lines)
    report_path = 'pe_reports/EVALUATION_REPORT.txt'
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report_text)
    
    print("\n" + "="*80)
    print(f"✓ Report saved: {report_path}")
    print("="*80)
    
    # Visualization
    try:
        fig, ax = plt.subplots(1, 1, figsize=(10, 6))
        metrics_df[['accuracy', 'precision', 'recall', 'f1_score', 'roc_auc']].plot(
            kind='bar', ax=ax, alpha=0.7
        )
        ax.set_title('Model Performance Comparison', fontsize=14, fontweight='bold')
        ax.set_ylabel('Score')
        ax.set_ylim([0, 1])
        ax.legend(loc='lower right')
        plt.xticks(rotation=0)
        plt.tight_layout()
        plt.savefig('pe_reports/performance.png', dpi=300, bbox_inches='tight')
        print("✓ Chart: pe_reports/performance.png")
        plt.close()
    except Exception as e:
        print(f"Warning: Visualization error: {e}")

if __name__ == "__main__":
    generate_report()
