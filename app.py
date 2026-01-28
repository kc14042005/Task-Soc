import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from pe_classifier import MalwareClassifier
from threat_classifier import ThreatClassifier
from phishing_dataset import PhishingFeatureExtractor
from brute_detector import BruteForceDetector
from brute_dataset import BruteForceDataset
from cve_predictor import CVESeverityPredictor
import numpy as np
import hashlib
import random
import joblib
import os
import json

st.set_page_config(
    page_title="SOC Analysis Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
    <style>
    .main {padding: 2rem;}
    </style>
""", unsafe_allow_html=True)

class WebScanner:
    def __init__(self):
        self.classifier = MalwareClassifier()
        self.loaded = False
    
    def load_model(self):
        if not self.loaded:
            success = self.classifier.load_model()
            if success:
                self.loaded = True
                return True, f"✓ Loaded: {self.classifier.best_model_name}"
            return False, "Model not found. Run train.py first."
        return True, "Model loaded"
    
    def extract_features_simulated(self, file_name):
        """Simulate feature extraction"""
        file_hash = hashlib.md5(file_name.encode()).digest()
        seed = int.from_bytes(file_hash[:4], 'big')
        np.random.seed(seed)
        
        is_suspicious = any(x in file_name.lower() for x in 
                          ['malware', 'virus', 'trojan', 'hack', 'crack', 'keygen'])
        
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
        
        return features

def generate_auto_examples():
    """Generate realistic SOC threat intelligence reports"""
    scenarios = {
        'Malware': [
            "Analysis of a recent infection chain reveals a new variant of the {family} {type}. The sample utilizes {obfuscation} to evade EDR solutions and establishes persistent access via {persistence}. C2 communications were observed targeting {c2_infra} using {protocol}.",
            "A high-volume email campaign is distributing the {family} {type}, targeting {target_sector}. The malware payload is capable of {capability1} and {capability2}. Initial access is achieved through {delivery_method}.",
            "Security researchers have identified a sophisticated {type} named '{family}'. This malicious software is specifically designed for {capability1} within {target_sector} environments. It leverages {obfuscation} and communicates with a decentralized {c2_infra}."
        ],
        'Phishing': [
            "A large-scale phishing operation is currently impersonating {brand} to harvest {credentials}. The attack utilizes {technique} and redirects victims to a highly realistic {brand} {landing_page}. Multiple {tld} domains have been registered for this campaign.",
            "Threat actors are targeting {target_sector} employees with sophisticated {type} emails. These messages claim to be {theme} and prompt users to click a link leading to a {landing_page}. The campaign uses {technique} to bypass traditional email filters.",
            "New {type} campaign detected using {theme} as a lure. Attackers are hosting malicious {landing_page} pages on {tld} domains. The objective is to steal {credentials} from {brand} customers."
        ],
        'Ransomware': [
            "The {group} ransomware group has claimed responsibility for an attack on {target_sector} infrastructure. The group utilized {entry_point} for initial access and moved laterally using {lateral_tool}. Data was exfiltrated to {storage} before the encryption phase.",
            "A new wave of {group} ransomware attacks is targeting {target_sector} organizations. The attackers are using a 'double extortion' tactic, threatening to leak sensitive data on their {leak_site} if the ransom is not paid. Initial access was likely gained via {entry_point}.",
            "Incident response analysis of a {group} ransomware event indicates the use of {lateral_tool} for internal reconnaissance. The threat actors successfully encrypted critical servers and demanded a payment in {crypto}. Evidence suggests data exfiltration to {storage} occurred prior to encryption."
        ],
        'DDoS': [
            "A massive {type} DDoS attack has been observed targeting {target_sector} web services. The attack reached a peak volume of {volume}, utilizing a botnet comprised of {botnet_type}. Mitigation efforts are ongoing as the attackers rotate through {technique} methods.",
            "DDoS extortion campaign is currently targeting global {target_sector} institutions. Threat actors are launching {type} attacks and demanding {crypto} to stop the disruption. The attacks leverage {technique} to saturate network bandwidth.",
            "Security monitors detected a sustained {type} DDoS event against {target_sector} APIs. The volumetric attack utilized {technique} amplification and originated from a global network of {botnet_type}. Traffic peaked at {volume} during the height of the event."
        ],
        'Data Breach': [
            "A major data breach at {brand} has exposed the personal records of approximately {record_count} users. The compromised data includes {data_types}. Investigation suggests the attackers exploited a {vulnerability} in an {infrastructure} component.",
            "Threat actors have successfully exfiltrated {record_count} sensitive records from a {target_sector} database. The breach was discovered after {data_types} appeared for sale on a dark web forum. The root cause appears to be a {vulnerability} in the {infrastructure}.",
            "Security audit at {brand} revealed an unauthorized access incident affecting {infrastructure}. An estimated {record_count} accounts had their {data_types} accessed. The breach is attributed to a {vulnerability} exploited by an external threat group."
        ],
        'Vulnerability': [
            "A critical {severity} vulnerability has been discovered in {brand} {product}. The flaw, tracked as {cve}, allows for {impact} via {vector}. Organizations are urged to apply the security patch immediately to prevent exploitation.",
            "Researchers have released a proof-of-concept for a {severity} vulnerability in {product}. The security issue enables {impact} if an attacker has {vector}. {brand} has confirmed reports of active exploitation in the wild.",
            "Analysis of {cve} reveals a {severity} flaw in {product}'s {infrastructure} handling. The vulnerability could lead to {impact} and is considered highly critical due to the {vector} requirements for successful execution."
        ]
    }
    
    vocab = {
        'family': ['CrimsonHydra', 'DarkGate', 'SilverTerrier', 'Emotet', 'Qakbot', 'IcedID'],
        'type': ['Backdoor', 'Infostealer', 'Trojan', 'RAT', 'Spyware', 'Downloader'],
        'obfuscation': ['polymorphic code', 'anti-analysis routines', 'multi-stage loading', 'process hollowing'],
        'persistence': ['WMI event subscriptions', 'Registry Run keys', 'Scheduled Tasks', 'DLL Search Order Hijacking'],
        'c2_infra': ['Cloudflare workers', 'compromised WordPress sites', 'Tor-based hidden services', 'fast-flux DNS networks'],
        'protocol': ['HTTPS tunneling', 'DNS exfiltration', 'custom RC4-encrypted TCP', 'WebSockets'],
        'target_sector': ['Financial', 'Healthcare', 'Government', 'Energy', 'Critical Infrastructure', 'Education'],
        'delivery_method': ['malicious macros', 'drive-by downloads', 'stolen RDP credentials', 'vulnerable edge devices'],
        'capability1': ['credential theft', 'screen capturing', 'keyboard logging', 'file encryption'],
        'capability2': ['lateral movement', 'network scanning', 'audio recording', 'privilege escalation'],
        'brand': ['Microsoft', 'Google', 'Amazon', 'PayPal', 'Chase Bank', 'Adobe'],
        'credentials': ['banking logins', 'session tokens', 'PII', 'MFA codes'],
        'technique': ['homograph domains', 'URL shortening services', 'HTML smuggling', 'CSS-based phishing'],
        'landing_page': ['login portal', 'account verification page', 'document previewer', 'password reset form'],
        'tld': ['.top', '.xyz', '.click', '.online', '.site', '.pw'],
        'theme': ['Urgent Security Update', 'Unpaid Invoice Notice', 'Account Suspension Warning', 'New Shared Document'],
        'group': ['LockBit', 'REvil', 'BlackCat', 'Conti', 'Cl0p', 'Medusa'],
        'entry_point': ['phishing with malicious attachments', 'exploiting unpatched VPNs', 'brute-forcing RDP', 'supply chain compromise'],
        'lateral_tool': ['Cobalt Strike', 'PowerShell Empire', 'Mimikatz', 'Adfind'],
        'storage': ['MEGA.nz', 'Google Drive', 'pCloud', 'custom FTP servers'],
        'leak_site': ['Tor-hosted leak blog', 'Telegram channel', 'public data dump site'],
        'crypto': ['Bitcoin (BTC)', 'Monero (XMR)'],
        'volume': ['1.2 Tbps', '800 Gbps', '500 Mpps', '2.5 Tbps'],
        'botnet_type': ['IoT devices', 'compromised routers', 'vulnerable cloud instances', 'mobile devices'],
        'record_count': ['500,000', '2 million', '50,000', '10 million'],
        'data_types': ['email addresses', 'SSNs', 'credit card numbers', 'health records'],
        'vulnerability': ['SQL injection', 'broken authentication', 'insecure API', 'misconfigured S3 bucket'],
        'infrastructure': ['web application firewall', 'legacy database server', 'cloud storage endpoint', 'authentication module'],
        'severity': ['CRITICAL', 'HIGH-SEVERITY', 'ZERO-DAY'],
        'product': ['Enterprise Server', 'Cloud Management Console', 'VPN Client', 'Core API Engine'],
        'cve': ['CVE-2023-4567', 'CVE-2024-1234', 'CVE-2023-9999'],
        'impact': ['remote code execution', 'full system compromise', 'unauthorized data access', 'denial of service'],
        'vector': ['unauthenticated network access', 'local privilege escalation', 'social engineering']
    }
    
    examples = {}
    for category, template_list in scenarios.items():
        template = random.choice(template_list)
        # Extract placeholders from template
        placeholders = [p.split('}')[0] for p in template.split('{')[1:]]
        fill_values = {p: random.choice(vocab[p]) for p in placeholders}
        examples[category] = template.format(**fill_values)
    
    return examples

def main():
    st.title("🛡️ SOC Analysis Dashboard")
    st.markdown("### Security Operations Center - ML-Powered Threat Detection")
    
    # Dashboard info
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.info("**📄 Threat Intel**\n- Category prediction\n- NLP Analysis")
    with col2:
        st.info("**🔍 PE Scanner**\n- Malware Detection\n- Static Analysis")
    with col3:
        st.info("**🔗 Phishing URL**\n- Risk Scoring\n- Feature Weights")
    with col4:
        st.info("**🛡️ Brute Force**\n- Log Analysis\n- Behavioral ML")
    with col5:
        st.info("**🏷️ CVE Predictor**\n- Severity Rating\n- CVSS Estimation")
    
    st.markdown("---")
    
    # Navigation
    tabs = st.tabs([
        "📄 Threat Intelligence", 
        "🔍 PE Malware Scanner", 
        "🔗 Phishing URL Detector",
        "🛡️ Brute Force Detector",
        "🏷️ CVE Severity Predictor"
    ])
    
    tab1, tab2, tab3, tab4, tab5 = tabs
    
    with tab1:
        threat_intelligence_page()
    
    with tab2:
        pe_malware_page()
        
    with tab3:
        phishing_url_page()

    with tab4:
        brute_force_page()

    with tab5:
        cve_severity_page()

def generate_phishing_url_examples():
    """Auto-generate realistic Phishing and Safe URLs"""
    brands = ['paypal', 'microsoft', 'google', 'amazon', 'apple', 'netflix', 'chase', 'wellsfargo', 'binance', 'coinbase']
    actions = ['login', 'verify', 'update', 'secure', 'account', 'billing', 'security', 'reset', 'support', 'signin']
    tlds = ['.xyz', '.top', '.pw', '.click', '.online', '.site', '.tk', '.ml', '.ga', '.cf', '.gq']
    safe_domains = ['google.com', 'microsoft.com', 'github.com', 'apple.com', 'amazon.com', 'wikipedia.org', 'nytimes.com', 'linkedin.com']
    
    examples = {
        'Safe URLs': [],
        'Phishing URLs': []
    }
    
    # Generate 3 safe
    for _ in range(3):
        domain = random.choice(safe_domains)
        path = random.choice(['search', 'about', 'contact', 'legal', 'help'])
        examples['Safe URLs'].append(f"https://www.{domain}/{path}")
        
    # Generate 3 phishing
    for _ in range(3):
        brand = random.choice(brands)
        action = random.choice(actions)
        tld = random.choice(tlds)
        pattern = random.choice([
            f"http://{brand}-{action}-portal{tld}/auth",
            f"http://{action}.{brand}-security-check{tld}/login",
            f"http://{brand}-account-update{tld}/verify"
        ])
        examples['Phishing URLs'].append(pattern)
        
    return examples

def regenerate_phish_examples():
    st.session_state.phish_examples = generate_phishing_url_examples()
    if 'phish_example_version' not in st.session_state:
        st.session_state.phish_example_version = 0
    st.session_state.phish_example_version += 1
    st.toast("New URL examples generated!", icon="🔗")

def phishing_url_page():
    """Phishing URL Detector page"""
    st.header("🔗 Phishing URL Detector")
    st.markdown("### Predict whether a URL is phishing or legitimate")
    
    # Load model
    try:
        model = joblib.load('phishing_models/best_model.pkl')
        scaler = joblib.load('phishing_models/scaler.pkl')
        with open('phishing_models/metadata.json', 'r') as f:
            metadata = json.load(f)
        extractor = PhishingFeatureExtractor()
        st.success(f"✓ Loaded: {metadata['best_model_name']}")
    except:
        st.error("Phishing model not found. Run: `python phishing_trainer.py` first.")
        return
        
    # Input
    st.subheader("🌐 Analyze URL")
    
    if 'phish_input' not in st.session_state:
        st.session_state.phish_input = ""
        
    url_input = st.text_input(
        "Enter URL to scan:",
        placeholder="https://example.com",
        key="phish_input"
    )
    
    col1, col2 = st.columns([1, 4])
    with col1:
        scan_btn = st.button("🔍 Scan URL", type="primary", use_container_width=True)
        
    if scan_btn and url_input:
        with st.spinner("Analyzing URL..."):
            features = extractor.extract_features(url_input)
            feature_names = extractor.get_feature_names()
            features_df = pd.DataFrame([features])[feature_names]
            
            X_scaled = scaler.transform(features_df)
            prediction = model.predict(X_scaled)[0]
            probability = model.predict_proba(X_scaled)[0][1]
            
            display_phishing_results(url_input, prediction, probability, features, model, feature_names)

    # Examples
    st.markdown("---")
    st.subheader("💡 Auto-Generated Examples")
    
    if 'phish_examples' not in st.session_state:
        st.session_state.phish_examples = generate_phishing_url_examples()
    if 'phish_example_version' not in st.session_state:
        st.session_state.phish_example_version = 0
        
    col1, col2 = st.columns(2)
    version = st.session_state.phish_example_version
    
    with col1:
        st.markdown("**Safe Examples:**")
        for i, url in enumerate(st.session_state.phish_examples['Safe URLs']):
            st.button(
                f"🟢 {url}", 
                key=f"ph_safe_auto_{i}_{version}", 
                on_click=update_phish_input, 
                args=(url,),
                use_container_width=True
            )
            
    with col2:
        st.markdown("**Phishing Examples:**")
        for i, url in enumerate(st.session_state.phish_examples['Phishing URLs']):
            st.button(
                f"🔴 {url}", 
                key=f"ph_mal_auto_{i}_{version}", 
                on_click=update_phish_input, 
                args=(url,),
                use_container_width=True
            )
            
    st.button("🔄 Generate New URL Examples", on_click=regenerate_phish_examples, use_container_width=True)

def update_phish_input(url):
    st.session_state.phish_input = url

def display_phishing_results(url, prediction, probability, features, model, feature_names):
    """Display phishing analysis results"""
    st.markdown("### 📊 Scan Results")
    
    # Verdict
    col1, col2, col3 = st.columns(3)
    with col1:
        if prediction == 1:
            st.metric("Verdict", "🔴 PHISHING", "High Risk")
        else:
            st.metric("Verdict", "🟢 LEGITIMATE", "Low Risk")
    with col2:
        st.metric("Risk Score", f"{probability*100:.1f}%")
    with col3:
        st.metric("Confidence", f"{abs(probability - 0.5) * 200:.1f}%")
        
    # Gauge
    fig = go.Figure(go.Indicator(
        mode = "gauge+number",
        value = probability * 100,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': "URL Risk Score", 'font': {'size': 20}},
        gauge = {
            'axis': {'range': [None, 100]},
            'bar': {'color': "red" if prediction == 1 else "green"},
            'steps': [
                {'range': [0, 30], 'color': 'lightgreen'},
                {'range': [30, 70], 'color': 'lightyellow'},
                {'range': [70, 100], 'color': 'lightcoral'}
            ]
        }
    ))
    fig.update_layout(height=300, margin=dict(l=20, r=20, t=50, b=20))
    st.plotly_chart(fig, use_container_width=True)
    
    # Feature Importance (Simple Explanation)
    if hasattr(model, 'feature_importances_'):
        st.markdown("### 🔍 Risk Factors (Top Features)")
        importances = model.feature_importances_
        indices = np.argsort(importances)[-5:]
        
        # Human readable mapping
        feature_map = {
            'url_length': 'URL Length',
            'domain_length': 'Domain Length',
            'num_dots': 'Number of Dots',
            'is_https': 'HTTPS Usage',
            'has_sensitive_keyword': 'Sensitive Keywords',
            'has_suspicious_tld': 'Suspicious TLD',
            'has_ip': 'IP Address in URL',
            'num_subdomains': 'Subdomains Count'
        }
        
        top_features = [feature_map.get(feature_names[i], feature_names[i]) for i in indices]
        top_scores = [importances[i] for i in indices]
        
        fig = go.Figure(go.Bar(
            x=top_scores,
            y=top_features,
            orientation='h',
            marker_color='red' if prediction == 1 else 'green'
        ))
        fig.update_layout(title="Top Features Contributing to Score", height=300)
        st.plotly_chart(fig, use_container_width=True)

    # Detailed report
    with st.expander("📋 Copy Scan Report"):
        verdict = "PHISHING" if prediction == 1 else "LEGITIMATE"
        report = f"""PHISHING SCAN REPORT
URL: {url}
Verdict: {verdict}
Risk Score: {probability*100:.1f}%

Key Features:
- Length: {features['url_length']}
- HTTPS: {'Yes' if features['is_https'] else 'No'}
- Suspicious TLD: {'Yes' if features['has_suspicious_tld'] else 'No'}
- Keywords: {'Yes' if features['has_sensitive_keyword'] else 'No'}"""
        st.code(report, language=None)


def update_threat_input(text):
    st.session_state.threat_input = text

def regenerate_threat_examples():
    st.session_state.auto_examples = generate_auto_examples()
    if 'threat_example_version' not in st.session_state:
        st.session_state.threat_example_version = 0
    st.session_state.threat_example_version += 1
    st.toast("New threat intelligence examples generated!", icon="🔄")

def threat_intelligence_page():
    """Threat Intelligence Text Classifier"""
    st.header("📄 Threat Intelligence Classifier")
    st.markdown("### Classify cyber threat reports into categories using NLP")
    
    # Load model
    classifier = ThreatClassifier()
    success = classifier.load_model()
    
    if not success:
        st.error("Model not found. Run: `python threat_train.py` to train the model")
        return
    
    st.success(f"✓ Loaded: {classifier.best_model_name}")
    
    # Model info banner
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("📊 Model", classifier.best_model_name)
    with col2:
        st.metric("📐 Features", "1000 TF-IDF")
    with col3:
        st.metric("🎯 Categories", len(classifier.categories))
    
    # Categories display
    st.markdown("**Available Threat Categories:**")
    cat_cols = st.columns(6)
    for i, cat in enumerate(classifier.categories):
        with cat_cols[i]:
            st.markdown(f"**{cat}**")
    
    st.markdown("---")
    
    # Text input
    st.subheader("📝 Enter Threat Report")
    
    # Initialize state
    if 'threat_input' not in st.session_state:
        st.session_state.threat_input = ""
        
    text_input = st.text_area(
        "Paste threat intelligence report or news article:",
        height=150,
        placeholder="Example: New ransomware campaign targets healthcare sector using phishing emails...",
        key="threat_input"
    )
    
    col1, col2 = st.columns([1, 4])
    with col1:
        analyze_btn = st.button("🔍 Analyze", type="primary", use_container_width=True)
    
    if analyze_btn and text_input:
        with st.spinner("Analyzing threat report..."):
            result = classifier.predict(text_input)
            display_threat_results(result, text_input)
    
    # Auto-generate examples
    st.markdown("---")
    st.header("💡 Auto-Generated Examples")
    
    # Generate example for each category
    if 'auto_examples' not in st.session_state:
        st.session_state.auto_examples = generate_auto_examples()
    if 'threat_example_version' not in st.session_state:
        st.session_state.threat_example_version = 0
    
    col1, col2, col3 = st.columns(3)
    cols = [col1, col2, col3]
    
    version = st.session_state.threat_example_version
    for i, (category, text) in enumerate(st.session_state.auto_examples.items()):
        with cols[i % 3]:
            st.button(
                f"📌 {category}", 
                key=f"ex_{category}_{version}", 
                on_click=update_threat_input, 
                args=(text,),
                use_container_width=True
            )
    
    # Generate new examples button
    st.button("🔄 Generate New Examples", on_click=regenerate_threat_examples, use_container_width=True)

def display_threat_results(result, text):
    """Display threat classification results"""
    st.markdown("### 📊 Analysis Results")
    
    category = result['category']
    confidence = result['confidence']
    probabilities = result['probabilities']
    key_terms = result['key_terms']
    
    # Copy report section
    with st.expander("📋 Copy Analysis Report"):
        report = f"""THREAT ANALYSIS REPORT
Category: {category}
Confidence: {confidence*100:.1f}%
Key Terms: {', '.join(key_terms)}
        
Input Text:
{text}"""
        st.code(report, language=None)
    
    # Category and confidence
    col1, col2 = st.columns(2)
    
    with col1:
        st.metric("🎯 Threat Category", category)
    
    with col2:
        st.metric("📊 Confidence", f"{confidence*100:.1f}%")
    
    # Key terms
    st.markdown("### 🔑 Key Terms Extracted")
    if key_terms:
        terms_html = " ".join([f"<span style='background-color: #ff4b4b; color: white; padding: 5px 10px; border-radius: 5px; margin: 5px; display: inline-block;'>{term}</span>" for term in key_terms])
        st.markdown(terms_html, unsafe_allow_html=True)
    else:
        st.info("No key terms found")
    
    # Probability distribution
    st.markdown("### 📈 Category Probabilities")
    
    sorted_probs = sorted(probabilities.items(), key=lambda x: x[1], reverse=True)
    categories = [p[0] for p in sorted_probs]
    probs = [p[1] * 100 for p in sorted_probs]
    
    fig = go.Figure(go.Bar(
        x=probs,
        y=categories,
        orientation='h',
        marker_color=['#ff4b4b' if cat == category else '#0068c9' for cat in categories],
        text=[f"{p:.1f}%" for p in probs],
        textposition='auto'
    ))
    fig.update_layout(
        title="Probability Distribution",
        xaxis_title="Probability (%)",
        yaxis_title="Category",
        height=400,
        showlegend=False
    )
    st.plotly_chart(fig, use_container_width=True)
    
    # Recommendations
    st.markdown("### 💡 Recommendations")
    
    recommendations = {
        'Malware': "🔴 Monitor for indicators of compromise (IOCs), update antivirus signatures, implement network segmentation.",
        'Phishing': "📧 Implement email filtering, conduct user awareness training, enable multi-factor authentication.",
        'Ransomware': "💾 Ensure offline backups, restrict admin privileges, patch systems regularly.",
        'DDoS': "🌐 Deploy DDoS mitigation services, implement rate limiting, use CDN services.",
        'Data Breach': "🔐 Notify affected parties, strengthen access controls, conduct forensic investigation.",
        'Vulnerability': "⚡ Apply patches immediately, implement workarounds, monitor for exploitation attempts."
    }
    
    if category in recommendations:
        st.info(recommendations[category])
    
    # Input text
    with st.expander("📄 View Input Text"):
        st.write(text)

def update_pe_input(text):
    st.session_state.pe_input = text

def generate_pe_filename_examples():
    """Auto-generate PE filename examples"""
    prefixes = ['win', 'sys', 'net', 'sec', 'host', 'svc', 'cloud', 'data', 'app', 'web']
    suffixes = ['32', '64', 'core', 'update', 'mgr', 'srv', 'agent', 'tool', 'lib', 'plugin']
    
    malware_keywords = ['malware', 'virus', 'trojan', 'hack', 'crack', 'keygen', 'injector', 'miner', 'rat', 'stealer']
    safe_keywords = ['notepad', 'calc', 'cmd', 'explorer', 'chrome', 'teams', 'excel', 'outlook', 'spotify', 'zoom']
    
    examples = {
        'Safe Files': [],
        'Malicious Files': []
    }
    
    used_names = set()
    
    # Generate 3 unique safe
    while len(examples['Safe Files']) < 3:
        if random.random() > 0.5:
            name = f"{random.choice(safe_keywords)}.exe"
        else:
            name = f"{random.choice(prefixes)}{random.choice(suffixes)}.exe"
        if name not in used_names:
            examples['Safe Files'].append(name)
            used_names.add(name)
        
    # Generate 3 unique malicious
    while len(examples['Malicious Files']) < 3:
        kw = random.choice(malware_keywords)
        if random.random() > 0.5:
            name = f"{kw}_{random.choice(suffixes)}.exe"
        else:
            name = f"installer_{kw}.exe"
        if name not in used_names:
            examples['Malicious Files'].append(name)
            used_names.add(name)
        
    return examples

def regenerate_pe_examples():
    st.session_state.pe_examples = generate_pe_filename_examples()
    if 'pe_example_version' not in st.session_state:
        st.session_state.pe_example_version = 0
    st.session_state.pe_example_version += 1
    st.toast("New PE filename examples generated!", icon="🔄")

def pe_malware_page():
    """PE Malware Scanner page"""
    st.header("🔍 PE Malware Scanner")
    st.markdown("### Static Analysis of Windows Executables using Machine Learning")
    
    scanner = WebScanner()
    success, message = scanner.load_model()
    
    if not success:
        st.error(message)
        st.info("Run: `python train.py` to train the model")
        return
    
    st.success(message)
    
    st.markdown("---")
    st.subheader("🔍 File Analysis")
    
    # File name input
    if 'pe_input' not in st.session_state:
        st.session_state.pe_input = ""
        
    file_name = st.text_input(
        "Enter PE file name to analyze:",
        placeholder="example.exe",
        help="Enter filename (simulation mode)",
        key="pe_input"
    )
    
    col1, col2 = st.columns([1, 4])
    with col1:
        analyze_button = st.button("🔍 Scan", type="primary", use_container_width=True)
    
    if analyze_button and file_name:
        with st.spinner("Analyzing PE file..."):
            # Extract features
            features = scanner.extract_features_simulated(file_name)
            features_list = list(features.values())
            
            # Predict
            result = scanner.classifier.predict(features_list)
            
            display_results(file_name, result, features, scanner)
    
    # Example files
    st.markdown("---")
    st.subheader("💡 Auto-Generated Examples")
    
    if 'pe_examples' not in st.session_state:
        st.session_state.pe_examples = generate_pe_filename_examples()
    if 'pe_example_version' not in st.session_state:
        st.session_state.pe_example_version = 0
    
    col1, col2 = st.columns(2)
    
    version = st.session_state.pe_example_version
    with col1:
        st.markdown("**Safe Examples:**")
        for i, example in enumerate(st.session_state.pe_examples['Safe Files']):
            st.button(
                f"🟢 {example}", 
                key=f"safe_auto_{i}_{example}_{version}", 
                on_click=update_pe_input, 
                args=(example,),
                use_container_width=True
            )
    
    with col2:
        st.markdown("**Malicious Examples:**")
        for i, example in enumerate(st.session_state.pe_examples['Malicious Files']):
            st.button(
                f"🔴 {example}", 
                key=f"mal_auto_{i}_{example}_{version}", 
                on_click=update_pe_input, 
                args=(example,),
                use_container_width=True
            )
            
    st.button("🔄 Generate New PE Examples", on_click=regenerate_pe_examples, use_container_width=True)

def display_results(file_name, result, features, scanner):
    """Display scan results"""
    st.markdown("### 📊 Scan Results")
    
    prediction = result['prediction']
    prob_malware = result['probability_malware']
    prob_benign = result['probability_benign']
    confidence = result['confidence']
    
    # Copy report section
    with st.expander("📋 Copy Scan Report"):
        verdict = "MALWARE" if prediction == 1 else "SAFE"
        report = f"""PE SCAN REPORT
File: {file_name}
Verdict: {verdict}
Confidence: {confidence*100:.1f}%
Malware Probability: {prob_malware*100:.1f}%
        
Key Indicators:
- Entropy: {features['entropy']:.2f}
- Suspicious Imports: {features['num_suspicious_imports']}
- Packer Detected: {'Yes' if features['packer_detected'] else 'No'}"""
        st.code(report, language=None)
    
    # Verdict
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if prediction == 1:
            st.metric("Verdict", "🔴 MALWARE", "High Risk")
        else:
            st.metric("Verdict", "🟢 SAFE", "Low Risk")
    
    with col2:
        if prediction == 1:
            st.metric("Malware Probability", f"{prob_malware*100:.1f}%")
        else:
            st.metric("Benign Probability", f"{prob_benign*100:.1f}%")
    
    with col3:
        st.metric("Confidence", f"{confidence*100:.1f}%")
    
    # Probability gauge
    st.markdown("### 📈 Risk Assessment")
    
    fig = go.Figure(go.Indicator(
        mode = "gauge+number",
        value = prob_malware * 100,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': "Malware Risk Score", 'font': {'size': 20}},
        gauge = {
            'axis': {'range': [None, 100], 'tickwidth': 1},
            'bar': {'color': "red" if prediction == 1 else "green"},
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 30], 'color': 'lightgreen'},
                {'range': [30, 70], 'color': 'lightyellow'},
                {'range': [70, 100], 'color': 'lightcoral'}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 70
            }
        }
    ))
    
    fig.update_layout(height=300, margin=dict(l=20, r=20, t=50, b=20))
    st.plotly_chart(fig, use_container_width=True)
    
    # Recommendations
    st.markdown("### 💡 Recommendations")
    if prediction == 1:
        st.error("""
        ⚠️ **WARNING: Potential Malware Detected**
        - Do NOT execute this file
        - Isolate from network
        - Submit for further analysis
        - Scan with multiple AV engines
        """)
    else:
        st.success("""
        ✓ **File appears safe**
        - No malicious indicators detected
        - Standard PE structure
        - Continue with caution
        """)
    
    # Feature analysis
    with st.expander("🔧 Detailed PE Features"):
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**File Characteristics:**")
            st.write(f"- File Size: {features['file_size']:,} bytes")
            st.write(f"- Sections: {features['num_sections']}")
            st.write(f"- Imports: {features['num_imports']}")
            st.write(f"- Exports: {features['num_exports']}")
            st.write(f"- Entropy: {features['entropy']:.2f}")
        
        with col2:
            st.markdown("**Security Indicators:**")
            st.write(f"- Digital Signature: {'Yes' if features['has_signature'] else 'No'}")
            st.write(f"- Debug Info: {'Yes' if features['has_debug'] else 'No'}")
            st.write(f"- Suspicious Imports: {features['num_suspicious_imports']}")
            st.write(f"- Packer Detected: {'Yes' if features['packer_detected'] else 'No'}")
            st.write(f"- Suspicious Sections: {features['suspicious_section_names']}")
    
    # Top features
    importance = scanner.classifier.get_feature_importance()
    if importance:
        with st.expander("📊 Top Risk Indicators"):
            top_features = list(importance.items())[:10]
            
            feature_names = [f[0] for f in top_features]
            feature_importance = [f[1] for f in top_features]
            
            fig = go.Figure(go.Bar(
                x=feature_importance,
                y=feature_names,
                orientation='h',
                marker_color='red' if prediction == 1 else 'green'
            ))
            fig.update_layout(
                title="Feature Importance",
                xaxis_title="Importance Score",
                yaxis_title="Feature",
                height=400
            )
            st.plotly_chart(fig, use_container_width=True)

def generate_cve_examples():
    """Auto-generate realistic CVE descriptions"""
    products = ['Enterprise VPN', 'Core API Engine', 'Web Server Pro', 'Database Express', 'Cloud Storage Gateway']
    vulnerabilities = [
        'Remote Code Execution (RCE)', 'SQL Injection', 'Cross-Site Scripting (XSS)', 
        'Privilege Escalation', 'Authentication Bypass', 'Buffer Overflow'
    ]
    components = ['authentication module', 'input validator', 'session manager', 'kernel driver', 'REST API endpoint']
    
    examples = {
        'Critical/High': [],
        'Medium/Low': []
    }
    
    # 3 Critical/High
    for _ in range(3):
        p = random.choice(products)
        v = random.choice(['Remote Code Execution', 'Authentication Bypass', 'Privilege Escalation'])
        c = random.choice(components)
        examples['Critical/High'].append(f"A critical {v} vulnerability in {p}'s {c} allows an unauthenticated attacker to gain full system control.")
        
    # 3 Medium/Low
    for _ in range(3):
        p = random.choice(products)
        v = random.choice(['Cross-Site Scripting', 'Information Disclosure', 'Open Redirect'])
        c = random.choice(components)
        examples['Medium/Low'].append(f"A {v} vulnerability exists in {p} due to improper sanitization in the {c}. This may lead to unauthorized data exposure.")
        
    return examples

def regenerate_cve_examples():
    st.session_state.cve_examples = generate_cve_examples()
    if 'cve_example_version' not in st.session_state:
        st.session_state.cve_example_version = 0
    st.session_state.cve_example_version += 1
    st.toast("New CVE examples generated!", icon="🏷️")

def update_cve_input(text):
    st.session_state.cve_input = text

def regenerate_brute_logs():
    ds = BruteForceDataset()
    ds.generate_data() # Force regenerate
    st.toast("New attack patterns generated in logs!", icon="🛡️")

def brute_force_page():
    """Brute Force Attack Detector page"""
    st.header("🛡️ Brute Force Attack Detector")
    st.markdown("### Detect brute-force attempts from authentication logs")
    
    detector = BruteForceDetector()
    try:
        detector.model = joblib.load('brute_models/brute_model.pkl')
        st.success("✓ Brute Force Model Loaded")
    except:
        st.error("Model not found. Run: `python brute_train.py` first.")
        return

    st.subheader("📊 Log Analysis")
    
    col1, col2 = st.columns([1, 4])
    with col1:
        analyze_brute = st.button("🚀 Run Detection", type="primary", use_container_width=True)
        st.button("🔄 Generate New Logs", on_click=regenerate_brute_logs, use_container_width=True)
    
    if analyze_brute:
        ds = BruteForceDataset()
        df = ds.load_data()
        alerts = detector.predict(df)
        if not alerts.empty:
            st.warning(f"🚨 Detected {len(alerts)} suspicious activity windows!")
            
            # Display alerts
            st.dataframe(alerts[['timestamp', 'source_ip', 'attempts', 'unique_users', 'confidence']].head(20), use_container_width=True)
            
            # Plot
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=alerts['timestamp'], y=alerts['attempts'], mode='markers', 
                                   marker=dict(size=10, color=alerts['confidence'], colorscale='Reds', showscale=True),
                                   text=alerts['source_ip']))
            fig.update_layout(title="Detected Attack Clusters (Attempts vs Time)", xaxis_title="Time", yaxis_title="Attempts")
            st.plotly_chart(fig, use_container_width=True)
            
            # Copy Report
            with st.expander("📋 Copy Alert Report"):
                top_ip = alerts.iloc[0]['source_ip']
                report = f"BRUTE FORCE ALERT\nIP: {top_ip}\nTotal Attack Windows: {len(alerts)}\nStatus: CRITICAL"
                st.code(report, language=None)
        else:
            st.success("✅ No brute force attacks detected in the logs.")

def cve_severity_page():
    """CVE Severity Predictor page"""
    st.header("🏷️ CVE Severity Predictor")
    st.markdown("### Predict vulnerability severity from description and metadata")
    
    predictor = CVESeverityPredictor()
    try:
        predictor.model = joblib.load('cve_models/cve_model.pkl')
        st.success("✓ CVE Predictor Model Loaded")
    except:
        st.error("Model not found. Run: `python cve_train.py` first.")
        return

    st.subheader("🔍 Analyze CVE")
    
    if 'cve_input' not in st.session_state:
        st.session_state.cve_input = ""
        
    desc_input = st.text_area(
        "CVE Description:", 
        placeholder="e.g., Remote code execution in kernel module...", 
        height=100,
        key="cve_input"
    )
    
    col1, col2 = st.columns(2)
    with col1:
        vector = st.selectbox("Attack Vector:", ['NETWORK', 'ADJACENT', 'LOCAL', 'PHYSICAL'])
    with col2:
        complexity = st.selectbox("Attack Complexity:", ['LOW', 'MEDIUM', 'HIGH'])
        
    if st.button("🎯 Predict Severity", type="primary"):
        if desc_input:
            res = predictor.predict(desc_input, vector, complexity)
            
            col1, col2, col3 = st.columns(3)
            with col1:
                color = {'CRITICAL': 'red', 'HIGH': 'orange', 'MEDIUM': 'yellow', 'LOW': 'green'}[res['severity']]
                st.markdown(f"### Severity: <span style='color:{color}'>{res['severity']}</span>", unsafe_allow_html=True)
            with col2:
                st.metric("Confidence", f"{res['confidence']:.2%}")
            with col3:
                st.markdown(f"**Key Terms:** {', '.join(res['top_keywords'])}")
                
            # Copy report
            with st.expander("📋 Copy CVE Report"):
                report = f"CVE SEVERITY REPORT\nDescription: {desc_input}\nPredicted Severity: {res['severity']}\nConfidence: {res['confidence']:.2%}\nKeywords: {', '.join(res['top_keywords'])}"
                st.code(report, language=None)
        else:
            st.warning("Please enter a CVE description.")

    # Examples
    st.markdown("---")
    st.subheader("💡 Auto-Generated Examples")
    
    if 'cve_examples' not in st.session_state:
        st.session_state.cve_examples = generate_cve_examples()
    if 'cve_example_version' not in st.session_state:
        st.session_state.cve_example_version = 0
        
    col1, col2 = st.columns(2)
    version = st.session_state.cve_example_version
    
    with col1:
        st.markdown("**Critical/High Examples:**")
        for i, text in enumerate(st.session_state.cve_examples['Critical/High']):
            st.button(
                f"🚨 {text[:40]}...", 
                key=f"cve_high_auto_{i}_{version}", 
                on_click=update_cve_input, 
                args=(text,),
                use_container_width=True
            )
            
    with col2:
        st.markdown("**Medium/Low Examples:**")
        for i, text in enumerate(st.session_state.cve_examples['Medium/Low']):
            st.button(
                f"🟡 {text[:40]}...", 
                key=f"cve_low_auto_{i}_{version}", 
                on_click=update_cve_input, 
                args=(text,),
                use_container_width=True
            )
            
    st.button("🔄 Generate New CVE Examples", on_click=regenerate_cve_examples, use_container_width=True)

if __name__ == "__main__":
    main()
