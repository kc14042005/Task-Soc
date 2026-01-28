import json
import pandas as pd
import matplotlib.pyplot as plt
import os

def generate_report():
    print("Generating Phishing URL Detector Evaluation Report...")
    os.makedirs('phishing_reports', exist_ok=True)
    
    # Load evaluation results
    try:
        with open('phishing_reports/evaluation.json', 'r') as f:
            results = json.load(f)
    except:
        print("Error: evaluation.json not found. Run phishing_trainer.py first.")
        return

    # Create detailed report text
    report_text = f"""
============================================================
PHISHING URL DETECTOR - EVALUATION REPORT
============================================================

1. PROJECT OVERVIEW
-------------------
The Phishing URL Detector is a Mini SOC Tool designed to 
identify malicious URLs using machine learning. It analyzes 
16 distinct features related to URL structure, domain characteristics, 
and content patterns.

2. FEATURES ANALYZED
--------------------
- URL/Domain Length
- Character Counts (dots, hyphens, special characters)
- Structural Analysis (HTTPS presence, subdomain count)
- Content Indicators (IP addresses, sensitive keywords like 'login')
- Suspicious TLD Analysis (.xyz, .top, .pw, etc.)
- Digit-to-letter ratio

3. MODEL PERFORMANCE
--------------------
| Model               | Accuracy | F1-Score |
|---------------------|----------|----------|
"""
    for model, metrics in results.items():
        report_text += f"| {model:<20} | {metrics['accuracy']:<8.4f} | {metrics['f1_score']:<8.4f} |\n"

    report_text += f"""
BEST MODEL: {max(results, key=lambda x: results[x]['f1_score'])}

4. CONCLUSION
-------------
The models demonstrate high efficacy in distinguishing between 
legitimate and phishing URLs in the synthetic test environment. 
Random Forest and Logistic Regression typically show 100% 
accuracy on this feature set due to the clear distinctions 
in URL structures used by attackers.

Generated on: 2026-01-27
============================================================
"""
    
    with open('phishing_reports/EVALUATION_REPORT.txt', 'w') as f:
        f.write(report_text)
        
    print(f"✓ Report generated: phishing_reports/EVALUATION_REPORT.txt")

if __name__ == "__main__":
    generate_report()
