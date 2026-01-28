import pandas as pd
import numpy as np
import os
import json

class CVEDataset:
    """Simulated CVE dataset generator based on NVD patterns"""
    
    def __init__(self, data_dir='cve_data'):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        
    def generate_data(self, n_samples=1000):
        print(f"Generating {n_samples} simulated CVE records...")
        
        # CVE terminology and patterns
        vocab = {
            'CRITICAL': [
                "remote code execution", "unauthenticated access", "buffer overflow in kernel",
                "rce via serialized object", "bypass authentication in administrative portal",
                "sql injection allows full database dump", "privilege escalation to root"
            ],
            'HIGH': [
                "cross-site scripting in search field", "denial of service via memory exhaustion",
                "directory traversal in web server", "information disclosure of sensitive configs",
                "insecure direct object reference", "misconfigured access control"
            ],
            'MEDIUM': [
                "stored xss in user profile", "session fixation in login",
                "improper input validation in api", "xml external entity (xxe) injection",
                "reflected xss in error page"
            ],
            'LOW': [
                "cookie without secure flag", "server version disclosure",
                "path disclosure in debug mode", "unsupported cipher suites"
            ]
        }
        
        attack_vectors = ['NETWORK', 'ADJACENT', 'LOCAL', 'PHYSICAL']
        complexities = ['LOW', 'MEDIUM', 'HIGH']
        
        data = []
        for severity, descriptions in vocab.items():
            count = n_samples // 4
            for _ in range(count):
                desc = np.random.choice(descriptions)
                # Add some noise/randomness
                extra = np.random.choice([" affects version 2.0.", " in legacy module.", " discovered in beta branch.", " exists in core component."])
                
                data.append({
                    'description': desc + extra,
                    'attack_vector': np.random.choice(attack_vectors, p=[0.6, 0.2, 0.15, 0.05]) if severity in ['CRITICAL', 'HIGH'] else np.random.choice(attack_vectors),
                    'complexity': 'LOW' if severity == 'CRITICAL' else np.random.choice(complexities),
                    'severity': severity
                })
        
        df = pd.DataFrame(data)
        # Map severity to numeric for model
        sev_map = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
        df['label'] = df['severity'].map(sev_map)
        
        path = os.path.join(self.data_dir, 'cve_records.csv')
        df.to_csv(path, index=False)
        print(f"✓ CVE data created: {path}")
        return df

    def load_data(self):
        path = os.path.join(self.data_dir, 'cve_records.csv')
        if not os.path.exists(path):
            return self.generate_data()
        return pd.read_csv(path)
