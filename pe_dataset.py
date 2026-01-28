import pandas as pd
import numpy as np
import os

class MalwareDataset:
    """Create sample PE malware dataset"""
    
    def __init__(self, data_dir='pe_data'):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
    
    def create_dataset(self):
        """Generate synthetic PE feature dataset"""
        print("Creating PE malware dataset...")
        
        np.random.seed(42)
        
        # Generate malware samples (50 samples)
        malware_samples = []
        for i in range(50):
            sample = {
                'file_name': f'malware_{i}.exe',
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
                'label': 1  # MALWARE
            }
            malware_samples.append(sample)
        
        # Generate benign samples (50 samples)
        benign_samples = []
        for i in range(50):
            sample = {
                'file_name': f'benign_{i}.exe',
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
                'label': 0  # BENIGN
            }
            benign_samples.append(sample)
        
        # Combine and save
        all_samples = malware_samples + benign_samples
        df = pd.DataFrame(all_samples)
        
        # Shuffle
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        dataset_path = os.path.join(self.data_dir, 'pe_features.csv')
        df.to_csv(dataset_path, index=False)
        
        print(f"✓ Dataset created: {dataset_path}")
        print(f"✓ Total samples: {len(df)}")
        print(f"  - Malware: {len(df[df['label']==1])}")
        print(f"  - Benign: {len(df[df['label']==0])}")
        print(f"✓ Features: {len(df.columns)-2}")
        
        return dataset_path
    
    def load_dataset(self, filename='pe_features.csv'):
        """Load PE dataset"""
        filepath = os.path.join(self.data_dir, filename)
        if not os.path.exists(filepath):
            print("Dataset not found. Creating...")
            self.create_dataset()
        
        df = pd.read_csv(filepath)
        print(f"\n✓ Loaded {len(df)} samples")
        return df
