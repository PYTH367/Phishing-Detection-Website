from flask import Flask, render_template, request, jsonify
import re
import whois
import requests
import datetime
import os
import socket

app = Flask(__name__)

# --- CONFIGURATION ---
# We use the provided key as a default, but allow environment variable override for security.
VT_API_KEY = os.environ.get('VT_API_KEY', 'a1ba4b60abc305710a603907b30bbeb08c48e419328c0ee9fc392e239bebb8f4')

def get_domain_from_url(url):
    try:
        domain = url.replace('https://', '').replace('http://', '').split('/')[0]
        return domain
    except:
        return ""

# --- LAYER 1: RULE-BASED ANALYSIS ---
def check_url_rules(url):
    score = 0
    reasons = []

    # 1. IP Address
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.search(ip_pattern, url):
        score += 2 # High impact
        reasons.append("URL contains an IP address instead of a domain")

    # 2. Length
    if len(url) > 75:
        score += 1
        reasons.append("URL length is suspiciously long (>75 chars)")

    # 3. @ Symbol
    if '@' in url:
        score += 2 # High impact
        reasons.append("URL contains '@' symbol (often used to obscure destination)")

    # 4. HTTPS Check
    if not url.startswith('https://'):
        score += 1
        reasons.append("Connection is not secure (No HTTPS)")

    # 5. Hyphens in domain
    domain = get_domain_from_url(url)
    if '-' in domain:
        score += 1
        reasons.append("Domain name contains hyphens (typosquatting technique)")

    # 6. Keywords
    keywords = ['login', 'verify', 'secure', 'bank', 'update', 'free', 'account', 'signin']
    found_keywords = [word for word in keywords if word in url.lower()]
    if found_keywords:
        score += 1
        reasons.append(f"URL contains suspicious urgent keywords: {', '.join(found_keywords)}")

    return score, reasons

# --- LAYER 2: DOMAIN AGE (WHOIS) ---
def check_domain_age(domain):
    reasons = []
    score = 0
    
    try:
        # Skip whois for IPs or empty domains
        if not domain or re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            return 0, []

        w = whois.whois(domain)
        creation_date = w.creation_date

        # Handle cases where creation_date is a list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            today = datetime.datetime.now()
            age = today - creation_date
            
            if age.days < 30:
                score += 3 # VERY High impact (New domains are dangerous)
                reasons.append(f"Domain is extremely new (Created {age.days} days ago)")
            elif age.days < 180: # 6 months
                score += 1
                reasons.append(f"Domain is relatively new (Created {age.days} days ago)")
    except Exception as e:
        # Whois lookup failed (private registration, timeout, or invalid domain)
        # We don't penalize heavily, but it's noted.
        pass
        
    return score, reasons

# --- LAYER 3: VIRUSTOTAL REPUTATION ---
def check_virustotal(url):
    reasons = []
    score = 0
    
    if not VT_API_KEY:
        return 0, ["VirusTotal scan skipped (No API Key)"]

    try:
        # Encode URL for VT API
        # Needs base64 url safe encoding without padding
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        headers = {
            "accept": "application/json",
            "x-apikey": VT_API_KEY
        }
        
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats['malicious']
            suspicious = stats['suspicious']
            
            if malicious > 0:
                score += 5 # Critical
                reasons.append(f"VirusTotal detected {malicious} security vendors flagging this URL")
            elif suspicious > 1:
                score += 2
                reasons.append(f"VirusTotal detected {suspicious} security vendors finding this suspicious")
        
        # Note: If 404, URL might be new to VT, so we submit it (optional, but keep simple for now)
        
    except Exception as e:
        reasons.append(f"VirusTotal check failed: {str(e)}")

    return score, reasons

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_url():
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({'error': 'Invalid request'}), 400
            
        url = data.get('url', '').strip()
        if not url:
            return jsonify({'error': 'No URL provided'}), 400

        # Initialize results
        total_score = 0
        all_reasons = []

        # --- EXECUTE LAYERS ---
        
        # Layer 1
        score1, reasons1 = check_url_rules(url)
        total_score += score1
        all_reasons.extend(reasons1)

        # Layer 2 (Domain extraction first)
        domain = get_domain_from_url(url)
        score2, reasons2 = check_domain_age(domain)
        total_score += score2
        all_reasons.extend(reasons2)

        # Layer 3
        # Only run if we have a key, logic inside handles it
        score3, reasons3 = check_virustotal(url)
        total_score += score3
        if score3 > 0: # Only add reasons if positive detection
            all_reasons.extend(reasons3)

        # --- FINAL DECISION LOGIC ---
        # Score Thresholds:
        # 0 = Safe
        # 1-2 = Suspicious
        # 3+ = Dangerous
        
        status = "safe"
        result_text = "🟢 SAFE"
        
        if total_score >= 3:
            status = "dangerous"
            result_text = "🔴 DANGEROUS"
        elif total_score >= 1:
            status = "suspicious"
            result_text = "🟠 SUSPICIOUS"
            
        # Special Override: If VT says malicious, it is DANGEROUS automatically
        for r in all_reasons:
            if "VirusTotal detected" in r and "malicious" in r:
                status = "dangerous"
                result_text = "🔴 DANGEROUS"
                break

        return jsonify({
            'result': result_text,
            'status': status,
            'reasons': all_reasons,
            'score': total_score 
        })
    except Exception as e:
        import traceback
        traceback.print_exc() # Print full error to terminal
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
