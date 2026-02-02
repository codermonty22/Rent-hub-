import re
import time
from collections import defaultdict

# Password policy: minimum 12 chars, uppercase, lowercase, digit, special char
def validate_strong_password(password):
    if len(password) < 12:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[^A-Za-z0-9]', password):
        return False
    return True

# Simple in-memory store for failed login attempts per user and IP
failed_login_attempts_user = defaultdict(list)  # key: user email, value: list of timestamps
failed_login_attempts_ip = defaultdict(list)    # key: IP address, value: list of timestamps

LOCKOUT_THRESHOLD = 5  # attempts
LOCKOUT_TIME = 15 * 60  # 15 minutes in seconds

def record_failed_login_user(email):
    now = time.time()
    failed_login_attempts_user[email].append(now)
    # Clean old attempts
    failed_login_attempts_user[email] = [t for t in failed_login_attempts_user[email] if now - t < LOCKOUT_TIME]

def record_failed_login_ip(ip):
    now = time.time()
    failed_login_attempts_ip[ip].append(now)
    # Clean old attempts
    failed_login_attempts_ip[ip] = [t for t in failed_login_attempts_ip[ip] if now - t < LOCKOUT_TIME]

def is_user_locked_out(email):
    attempts = failed_login_attempts_user.get(email, [])
    return len(attempts) >= LOCKOUT_THRESHOLD

def is_ip_locked_out(ip):
    attempts = failed_login_attempts_ip.get(ip, [])
    return len(attempts) >= LOCKOUT_THRESHOLD

def reset_failed_logins(email, ip):
    if email in failed_login_attempts_user:
        del failed_login_attempts_user[email]
    if ip in failed_login_attempts_ip:
        del failed_login_attempts_ip[ip]
