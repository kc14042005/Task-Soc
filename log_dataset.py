import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import os

class LogDataset:
    """Generate synthetic security log dataset"""
    
    def __init__(self, data_dir='log_data'):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
    
    def create_dataset(self):
        """Generate synthetic security logs"""
        print("Creating security log dataset...")
        
        np.random.seed(42)
        
        # Normal logs (800 samples)
        normal_logs = []
        base_time = datetime.now() - timedelta(days=7)
        
        normal_users = ['admin', 'user1', 'user2', 'dbadmin', 'webadmin']
        normal_ips = ['192.168.1.100', '192.168.1.101', '192.168.1.102', '10.0.0.50', '10.0.0.51']
        normal_actions = ['login_success', 'logout', 'file_access', 'service_start', 'config_read']
        
        for i in range(800):
            timestamp = base_time + timedelta(minutes=i*5)
            log = {
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'user': np.random.choice(normal_users),
                'source_ip': np.random.choice(normal_ips),
                'action': np.random.choice(normal_actions),
                'status': 'success',
                'session_duration': np.random.randint(60, 3600),
                'bytes_transferred': np.random.randint(1000, 100000),
                'failed_attempts': 0,
                'privilege_level': np.random.choice([1, 2], p=[0.9, 0.1]),
                'is_anomaly': 0
            }
            normal_logs.append(log)
        
        # Anomalous logs (200 samples)
        anomaly_logs = []
        
        # Type 1: Brute force attempts
        for i in range(50):
            timestamp = base_time + timedelta(minutes=np.random.randint(0, 10080))
            log = {
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'user': np.random.choice(['root', 'administrator', 'unknown']),
                'source_ip': f"{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}",
                'action': 'login_failed',
                'status': 'failed',
                'session_duration': 0,
                'bytes_transferred': 0,
                'failed_attempts': np.random.randint(5, 50),
                'privilege_level': 0,
                'is_anomaly': 1
            }
            anomaly_logs.append(log)
        
        # Type 2: Unusual time access
        for i in range(50):
            timestamp = base_time + timedelta(days=np.random.randint(0, 7), hours=np.random.randint(0, 6))
            log = {
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'user': np.random.choice(normal_users),
                'source_ip': np.random.choice(normal_ips),
                'action': np.random.choice(['admin_access', 'config_change', 'user_create']),
                'status': 'success',
                'session_duration': np.random.randint(1800, 7200),
                'bytes_transferred': np.random.randint(500000, 5000000),
                'failed_attempts': 0,
                'privilege_level': 3,
                'is_anomaly': 1
            }
            anomaly_logs.append(log)
        
        # Type 3: Suspicious data exfiltration
        for i in range(50):
            timestamp = base_time + timedelta(minutes=np.random.randint(0, 10080))
            log = {
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'user': np.random.choice(normal_users),
                'source_ip': np.random.choice(normal_ips),
                'action': 'data_transfer',
                'status': 'success',
                'session_duration': np.random.randint(3600, 28800),
                'bytes_transferred': np.random.randint(10000000, 100000000),
                'failed_attempts': 0,
                'privilege_level': 2,
                'is_anomaly': 1
            }
            anomaly_logs.append(log)
        
        # Type 4: Privilege escalation
        for i in range(50):
            timestamp = base_time + timedelta(minutes=np.random.randint(0, 10080))
            log = {
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'user': np.random.choice(['user1', 'user2']),
                'source_ip': np.random.choice(normal_ips),
                'action': 'privilege_escalation',
                'status': 'success',
                'session_duration': np.random.randint(300, 1800),
                'bytes_transferred': np.random.randint(5000, 50000),
                'failed_attempts': np.random.randint(1, 3),
                'privilege_level': 3,
                'is_anomaly': 1
            }
            anomaly_logs.append(log)
        
        # Combine and shuffle
        all_logs = normal_logs + anomaly_logs
        df = pd.DataFrame(all_logs)
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # Save
        dataset_path = os.path.join(self.data_dir, 'security_logs.csv')
        df.to_csv(dataset_path, index=False)
        
        print(f"✓ Dataset: {dataset_path}")
        print(f"✓ Total logs: {len(df)}")
        print(f"  - Normal: {len(df[df['is_anomaly']==0])}")
        print(f"  - Anomalies: {len(df[df['is_anomaly']==1])}")
        
        return dataset_path
    
    def load_dataset(self, filename='security_logs.csv'):
        """Load log dataset"""
        filepath = os.path.join(self.data_dir, filename)
        if not os.path.exists(filepath):
            print("Dataset not found. Creating...")
            self.create_dataset()
        
        df = pd.read_csv(filepath)
        print(f"\n✓ Loaded {len(df)} logs")
        return df
