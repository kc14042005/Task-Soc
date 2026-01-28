import pandas as pd
import numpy as np
import os
import re
from urllib.parse import urlparse

class PhishingFeatureExtractor:
    """Extract features from URLs for phishing detection"""
    
    def __init__(self):
        self.suspicious_tlds = ['.xyz', '.top', '.pw', '.click', '.club', '.online', '.site', '.tk', '.ml', '.ga', '.cf', '.gq']
        self.sensitive_keywords = ['login', 'bank', 'account', 'update', 'verify', 'secure', 'ebay', 'paypal', 'microsoft', 'office', 'amazon', 'signin', 'wallet']
        
    def extract_features(self, url):
        """Extract features from a single URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
        except:
            domain = ""
            path = ""
            
        features = {}
        
        # 1. Length features
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        
        # 2. Count features
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_at'] = url.count('@')
        features['num_question'] = url.count('?')
        features['num_equal'] = url.count('=')
        features['num_amp'] = url.count('&')
        features['num_percent'] = url.count('%')
        features['num_slash'] = url.count('/')
        
        # 3. Structural features
        features['num_subdomains'] = max(0, domain.count('.') - 1)
        features['is_https'] = 1 if url.startswith('https://') else 0
        
        # 4. Content features
        features['has_ip'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) else 0
        features['has_sensitive_keyword'] = 1 if any(kw in url.lower() for kw in self.sensitive_keywords) else 0
        features['has_suspicious_tld'] = 1 if any(url.lower().endswith(tld) for tld in self.suspicious_tlds) else 0
        
        # 5. Ratios
        num_digits = sum(c.isdigit() for c in url)
        num_letters = sum(c.isalpha() for c in url)
        features['digit_letter_ratio'] = num_digits / (num_letters + 1)
        
        return features

    def get_feature_names(self):
        return [
            'url_length', 'domain_length', 'num_dots', 'num_hyphens', 
            'num_at', 'num_question', 'num_equal', 'num_amp', 
            'num_percent', 'num_slash', 'num_subdomains', 'is_https', 
            'has_ip', 'has_sensitive_keyword', 'has_suspicious_tld', 
            'digit_letter_ratio'
        ]

class PhishingDataset:
    """Generate and load phishing URL dataset"""
    
    def __init__(self, data_dir='phishing_data'):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.extractor = PhishingFeatureExtractor()
        
    def generate_synthetic_data(self):
        """Generate synthetic URLs for training"""
        print("Generating synthetic phishing dataset...")
        
        legitimate_urls = [
            "https://www.google.com", "https://www.microsoft.com", "https://www.amazon.com",
            "https://www.github.com", "https://www.wikipedia.org", "https://www.nytimes.com",
            "https://www.apple.com", "https://www.linkedin.com", "https://www.reddit.com",
            "https://www.netflix.com", "https://www.stackoverflow.com", "https://www.cnn.com",
            "https://www.bbc.com", "https://www.ebay.com", "https://www.paypal.com",
            "https://www.facebook.com", "https://www.twitter.com", "https://www.instagram.com",
            "https://www.adobe.com", "https://www.zoom.us", "https://www.dropbox.com",
            "https://www.salesforce.com", "https://www.medium.com", "https://www.quora.com",
            "https://www.spotify.com", "https://www.twitch.tv", "https://www.hulu.com",
            "https://www.disneyplus.com", "https://www.airbnb.com", "https://www.booking.com"
        ]
        
        phishing_urls = [
            "http://login-microsoft-office365.online/verify", "http://paypal-security-update.xyz/login",
            "http://amazon-account-support.site/billing", "http://wellsfargo-verify-identity.top/secure",
            "http://apple-icloud-login.pw/sign-in", "http://192.168.1.1/login.html",
            "http://google-drive-share.click/doc-view", "http://microsoft-outlook-web.tk/auth",
            "http://netflix-billing-issue.ml/update", "http://facebook-security-check.ga/profile",
            "http://secure-banking-access.cf/login", "http://verify-your-wallet.gq/seed",
            "http://amazon-prime-deals-click.pw/offers", "http://ebay-resolution-center.site/dispute",
            "http://paypal-gift-card-free.online/claim", "http://bankofamerica-login-secure.xyz/access",
            "http://chase-online-banking-update.top/verify", "http://irs-tax-refund-status.click/check",
            "http://dhl-package-tracking-info.pw/delivery", "http://ups-delivery-failed.site/reschedule",
            "http://google-account-recovery-security.ml/reset", "http://microsoft-365-admin-login.ga/portal",
            "http://dropbox-shared-file-access.cf/download", "http://zoom-meeting-invite-join.gq/lobby",
            "http://adobe-flash-player-update.online/install", "http://wallet-connect-sync.xyz/auth",
            "http://binance-login-secure-access.site/trade", "http://coinbase-account-verify.top/security",
            "http://blockchain-wallet-backup.pw/restore", "http://metamask-extension-update.click/login"
        ]
        
        data = []
        for url in legitimate_urls:
            features = self.extractor.extract_features(url)
            features['url'] = url
            features['label'] = 0  # Legitimate
            data.append(features)
            
        for url in phishing_urls:
            features = self.extractor.extract_features(url)
            features['url'] = url
            features['label'] = 1  # Phishing
            data.append(features)
            
        df = pd.DataFrame(data)
        dataset_path = os.path.join(self.data_dir, 'phishing_dataset.csv')
        df.to_csv(dataset_path, index=False)
        print(f"✓ Synthetic dataset created: {dataset_path}")
        return df

    def load_dataset(self):
        """Load dataset, generate if doesn't exist"""
        dataset_path = os.path.join(self.data_dir, 'phishing_dataset.csv')
        if not os.path.exists(dataset_path):
            return self.generate_synthetic_data()
        return pd.read_csv(dataset_path)
