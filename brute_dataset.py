import pandas as pd
import numpy as np
import os
from datetime import datetime, timedelta

class BruteForceDataset:
    """Generate synthetic login logs with brute force patterns"""
    
    def __init__(self, data_dir='login_data'):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        
    def generate_data(self, n_logs=2000):
        print(f"Generating {n_logs} synthetic login logs...")
        
        # Base settings
        start_time = datetime(2026, 1, 1, 0, 0, 0)
        users = ['admin', 'user1', 'user2', 'db_admin', 'webmaster', 'guest', 'support']
        ips = [f"192.168.1.{i}" for i in range(10, 50)]
        external_ips = [f"203.0.113.{i}" for i in range(1, 10)]
        
        data = []
        
        # 1. Normal Traffic (~85%)
        n_normal = int(n_logs * 0.85)
        for i in range(n_normal):
            ts = start_time + timedelta(seconds=i * 30 + np.random.randint(0, 60))
            ip = np.random.choice(ips)
            user = np.random.choice(users)
            status = np.random.choice(['success', 'failed'], p=[0.9, 0.1])
            data.append({
                'timestamp': ts,
                'source_ip': ip,
                'username': user,
                'status': status,
                'label': 0 # Normal
            })
            
        # 2. Brute Force Patterns (~15%)
        attack_ips = [f"10.0.0.{i}" for i in range(1, 20)]
        
        # Scenario 1: High-volume classic brute force
        for ip in attack_ips[:5]:
            start = start_time + timedelta(hours=np.random.randint(1, 23))
            for i in range(200):
                ts = start + timedelta(seconds=i * 0.5)
                data.append({
                    'timestamp': ts,
                    'source_ip': ip,
                    'username': 'admin',
                    'status': 'failed',
                    'label': 1
                })

        # Scenario 2: Distributed credential stuffing
        for i in range(300):
            ts = start_time + timedelta(hours=15) + timedelta(seconds=i * 2)
            data.append({
                'timestamp': ts,
                'source_ip': np.random.choice(attack_ips[5:15]),
                'username': f"user_{i}",
                'status': 'failed',
                'label': 1
            })
            
        # Scenario 3: Successful brute force
        attacker_ip = "1.2.3.4"
        start = start_time + timedelta(hours=20)
        for i in range(50):
            ts = start + timedelta(seconds=i)
            status = 'failed' if i < 49 else 'success'
            data.append({
                'timestamp': ts,
                'source_ip': attacker_ip,
                'username': 'root',
                'status': status,
                'label': 1
            })
            
        df = pd.DataFrame(data)
        df = df.sort_values('timestamp').reset_index(drop=True)
        
        path = os.path.join(self.data_dir, 'login_logs.csv')
        df.to_csv(path, index=False)
        print(f"✓ Logs created: {path}")
        return df

    def load_data(self):
        path = os.path.join(self.data_dir, 'login_logs.csv')
        if not os.path.exists(path):
            return self.generate_data()
        return pd.read_csv(path, parse_dates=['timestamp'])
