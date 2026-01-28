import pandas as pd
import numpy as np
import os

class ThreatDataset:
    """Generate synthetic threat intelligence dataset"""
    
    def __init__(self, data_dir='threat_data'):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
    
    def create_dataset(self):
        """Generate synthetic threat reports"""
        print("Creating threat intelligence dataset...")
        
        # Define threat categories with sample texts
        threat_samples = {
            'Malware': [
                'New trojan variant discovered spreading through email attachments. The malware uses advanced obfuscation techniques and establishes persistence through registry modifications. Analysis shows it communicates with C2 servers.',
                'Sophisticated backdoor malware detected targeting financial institutions. The malicious software uses DLL injection and API hooking to steal credentials.',
                'Ransomware payload delivered via compromised software updates. The malware encrypts files and demands payment in cryptocurrency.',
                'Spyware campaign targets mobile devices through fake applications. The malicious app harvests contacts, messages, and location data.',
                'Botnet malware spreading through vulnerable IoT devices. Infected devices are used for DDoS attacks and cryptocurrency mining.',
                'Advanced persistent threat group deploys custom malware toolset. The malware family includes keyloggers, screen capture utilities, and data exfiltration tools.',
                'Polymorphic virus detected evading signature-based detection. The malware changes its code structure while maintaining functionality.',
                'Fileless malware uses PowerShell scripts and WMI for execution. No files are written to disk making detection difficult.',
                'Remote access trojan spread through malicious macros in Office documents. Enables complete system control.',
                'Cryptominer malware consumes system resources for cryptocurrency mining. Significantly degrades system performance.',
            ],
            'Phishing': [
                'Mass phishing campaign targets corporate email accounts using fake Microsoft 365 login pages. Credentials harvested through spoofed domains.',
                'Spear phishing attacks target executives with personalized emails containing malicious links. Attackers conducted social engineering research.',
                'SMS phishing campaign impersonates delivery services. Messages contain links to fake tracking pages requesting personal information.',
                'Email phishing attempt uses coronavirus theme to distribute malware. Attachments claim to contain health information.',
                'Whaling attack targets C-level executives with fake legal notices. Emails contain urgent requests for wire transfers.',
                'Phishing kit sold on dark web automates credential theft. Templates mimic popular banking and social media sites.',
                'Business email compromise scam tricks finance departments. Attackers impersonate executives requesting urgent payments.',
                'Phishing campaign exploits recent data breach notifications. Victims receive fake security alerts requesting account verification.',
                'Voice phishing attacks target elderly victims claiming IRS issues. Scammers use social engineering tactics.',
                'QR code phishing distributes malicious payment requests. Codes lead to credential harvesting sites.',
            ],
            'Ransomware': [
                'Ransomware gang encrypts hospital systems demanding seven-figure ransom. Patient care severely impacted by the attack.',
                'Double extortion ransomware threatens to leak stolen data. Attackers exfiltrate sensitive information before encryption.',
                'Ransomware-as-a-service operation targets small businesses. Affiliate program attracts criminal operators worldwide.',
                'Supply chain attack delivers ransomware through managed service provider. Multiple organizations simultaneously compromised.',
                'Ransomware operators exploit VPN vulnerabilities for initial access. Weak credentials enable network penetration.',
                'New ransomware variant targets cloud storage and backups. Organizations left without recovery options.',
                'Ransomware attack disrupts critical infrastructure. Energy sector facilities experience operational shutdowns.',
                'Ransomware negotiation tactics evolve with professional support services. Attackers offer decryption guarantees.',
                'Ransomware deployed through compromised remote desktop services. Brute force attacks on RDP ports succeed.',
                'Ransomware encrypts virtual machine backups. Disaster recovery plans rendered ineffective.',
            ],
            'DDoS': [
                'Massive DDoS attack overwhelms major websites using IoT botnet. Traffic exceeds 1 Tbps causing prolonged outages.',
                'Application layer DDoS attack targets API endpoints. Sophisticated requests bypass traditional mitigation.',
                'Amplification DDoS attack exploits misconfigured DNS servers. Small queries generate massive response traffic.',
                'DDoS extortion campaign threatens attacks unless ransom paid. Multiple organizations receive identical threats.',
                'Distributed denial of service attack targets gaming platforms. Players unable to access online services.',
                'Reflection attack amplifies traffic 50x using NTP servers. Volumetric attack saturates network bandwidth.',
                'Low and slow DDoS attack evades detection systems. Gradual resource exhaustion causes service degradation.',
                'Multi-vector DDoS combines volumetric and application attacks. Mitigation strategies struggle with complexity.',
                'DDoS attack targets financial services during peak hours. Transaction processing severely impacted.',
                'Memcached DDoS amplification reaches record bandwidth. Reflection ratio enables massive attacks.',
            ],
            'Data Breach': [
                'Major data breach exposes millions of customer records. Personal information including names, addresses, and SSNs compromised.',
                'Healthcare provider suffers breach affecting patient data. Protected health information accessed by unauthorized parties.',
                'Credit card breach at retail chain compromises payment data. Point-of-sale systems infected with card-skimming malware.',
                'Cloud misconfiguration leads to exposure of sensitive documents. Public S3 bucket contained confidential business data.',
                'Insider threat results in unauthorized data exfiltration. Employee downloads customer database before resignation.',
                'Third-party vendor breach affects multiple organizations. Supply chain security weaknesses exploited.',
                'Database exposed online without password protection. Millions of records accessible to anyone on internet.',
                'Data breach notification reveals year-long compromise. Sophisticated attackers maintained persistent access.',
                'Financial institution breach exposes transaction history. Account numbers and routing information stolen.',
                'Social media breach leaks user profile information. Email addresses and phone numbers compromised.',
            ],
            'Vulnerability': [
                'Critical zero-day vulnerability discovered in widely-used software. Remote code execution possible without authentication.',
                'Patch released for actively exploited security flaw. Attackers targeting unpatched systems in the wild.',
                'Buffer overflow vulnerability allows arbitrary code execution. Memory corruption can be triggered remotely.',
                'SQL injection vulnerability found in web application. Database contents can be extracted or modified.',
                'Cross-site scripting flaw enables session hijacking. User credentials can be stolen through malicious scripts.',
                'Authentication bypass vulnerability discovered in VPN software. Attackers gain unauthorized network access.',
                'Privilege escalation vulnerability allows local attackers to gain admin rights. Kernel-level exploitation possible.',
                'Cryptographic weakness in protocol implementation. Encrypted communications can be decrypted.',
                'Directory traversal vulnerability permits arbitrary file access. Sensitive system files exposed to attackers.',
                'Deserialization vulnerability enables remote command execution. Untrusted data processing leads to compromise.',
            ]
        }
        
        # Generate dataset
        data = []
        for category, samples in threat_samples.items():
            for text in samples:
                data.append({
                    'text': text,
                    'category': category
                })
        
        df = pd.DataFrame(data)
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # Save
        dataset_path = os.path.join(self.data_dir, 'threat_reports.csv')
        df.to_csv(dataset_path, index=False)
        
        print(f"✓ Dataset: {dataset_path}")
        print(f"✓ Total reports: {len(df)}")
        for category in df['category'].unique():
            count = len(df[df['category'] == category])
            print(f"  - {category}: {count}")
        
        return dataset_path
    
    def load_dataset(self, filename='threat_reports.csv'):
        """Load threat dataset"""
        filepath = os.path.join(self.data_dir, filename)
        if not os.path.exists(filepath):
            print("Dataset not found. Creating...")
            self.create_dataset()
        
        df = pd.read_csv(filepath)
        print(f"\n✓ Loaded {len(df)} reports")
        return df
