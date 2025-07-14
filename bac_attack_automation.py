import requests
import time
import csv
import random
import jwt
import json
import numpy as np
import pandas as pd
from faker import Faker
import datetime
import concurrent.futures
import ipaddress
from collections import defaultdict, Counter
import uuid
import hashlib
import os
from urllib.parse import urlparse, parse_qs
import threading

# Initialize Faker for generating realistic user data
fake = Faker()

BASE_URLS = {
    "dvwa": "http://localhost:8081",
    "webgoat": "http://localhost:8080",
    "juice_shop": "http://localhost:3000"
}

# Output files
bac_results_file = "enhanced_bac_results.csv"
user_behavior_file = "user_behavior_profiles.json"
resource_access_patterns_file = "resource_access_patterns.json"

ROLES = ["Guest", "User", "Admin", "Malicious"]
JWT_SECRET = "fake_secret_key"

# Add thread locks for shared data structures
session_data_lock = threading.Lock()
resource_access_lock = threading.Lock()
access_times_lock = threading.Lock()
endpoint_failures_lock = threading.Lock()
ip_addresses_lock = threading.Lock()

# Time windows for rate limiting and behavior analysis
TIME_WINDOWS = {
    "short": 5 * 60,  # 5 minutes in seconds
    "medium": 30 * 60,  # 30 minutes in seconds
    "long": 24 * 60 * 60  # 24 hours in seconds
}

# Create data structures to track user behavior
user_session_data = defaultdict(list)
user_resource_access = defaultdict(Counter)
resource_access_frequency = defaultdict(int)
user_access_times = defaultdict(list)
endpoint_failure_rates = defaultdict(lambda: {"attempts": 0, "failures": 0})
user_ip_addresses = defaultdict(set)
user_geolocation = defaultdict(dict)
user_device_fingerprints = {}

# Function to generate fake JWTs for different roles
def generate_jwt(role, user_id=None):
    if user_id is None:
        user_id = random.randint(1, 50)
    
    payload = {
        "id": user_id,
        "username": fake.user_name(),
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600  # 1 hour expiration
    }
    
    # For malicious tokens, try to escalate privileges but keep original user ID
    if role == "Malicious":
        original_role = random.choice(["Guest", "User"])
        payload["original_role"] = original_role
        payload["role"] = "Admin"  # Attempt privilege escalation
    
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256"), user_id

# Generate device fingerprint
def generate_device_fingerprint():
    browser = random.choice(["Chrome", "Firefox", "Safari", "Edge", "Opera"])
    os_type = random.choice(["Windows", "MacOS", "Linux", "iOS", "Android"])
    screen_res = random.choice(["1920x1080", "1366x768", "2560x1440", "750x1334", "1280x800"])
    lang = random.choice(["en-US", "es-ES", "fr-FR", "de-DE", "zh-CN", "ja-JP"])
    timezone = random.choice(["UTC", "UTC+1", "UTC-5", "UTC+9", "UTC+8"])
    
    fingerprint_data = f"{browser}|{os_type}|{screen_res}|{lang}|{timezone}"
    return hashlib.md5(fingerprint_data.encode()).hexdigest(), {
        "browser": browser,
        "os": os_type,
        "resolution": screen_res,
        "language": lang,
        "timezone": timezone
    }

# Generate geographical data consistent with IP
def generate_geo_data(ip_address):
    continent = random.choice(["NA", "EU", "AS", "SA", "AF", "OC"])
    country = fake.country_code()
    city = fake.city()
    
    return {
        "ip": ip_address,
        "continent": continent,
        "country": country,
        "city": city,
        "coordinates": [float(fake.longitude()), float(fake.latitude())]
    }

attack_endpoints = [
    {"url": "/api/user/{id}", "method": "GET", "expected": "Depends on Role", "resource_type": "user", "classification": "restricted", "sensitivity": "medium"},
    {"url": "/api/admin", "method": "GET", "expected": "Denied", "resource_type": "admin_panel", "classification": "restricted", "sensitivity": "high"},
    {"url": "/api/orders/{id}", "method": "GET", "expected": "Depends on Ownership", "resource_type": "order", "classification": "internal", "sensitivity": "medium"},
    {"url": "/api/orders/{id}", "method": "DELETE", "expected": "Admin Only", "resource_type": "order", "classification": "restricted", "sensitivity": "high"},
    {"url": "/api/products/{id}", "method": "PUT", "expected": "Admin Only", "resource_type": "product", "classification": "restricted", "sensitivity": "high"},
    {"url": "/api/payments/{id}", "method": "GET", "expected": "Owner/Admin Only", "resource_type": "payment", "classification": "restricted", "sensitivity": "high"},
    {"url": "/api/payments/process", "method": "POST", "expected": "Admin Only", "resource_type": "payment", "classification": "restricted", "sensitivity": "high"},
    {"url": "/api/transactions", "method": "GET", "expected": "Admin Only", "resource_type": "transaction", "classification": "restricted", "sensitivity": "high"},
    {"url": "/api/account/change-password", "method": "POST", "expected": "User Only", "resource_type": "account", "classification": "internal", "sensitivity": "high"},
    {"url": "/api/account/delete", "method": "POST", "expected": "Admin Only", "resource_type": "account", "classification": "restricted", "sensitivity": "high"},
    {"url": "/api/user/{id}/role", "method": "PUT", "expected": "Admin Only", "resource_type": "user", "classification": "restricted", "sensitivity": "high"},
    {"url": "/hidden_admin_portal", "method": "GET", "expected": "Denied", "resource_type": "admin_panel", "classification": "restricted", "sensitivity": "high"},
]

# Additional benign endpoints for more realistic traffic patterns
benign_endpoints = [
    {"url": "/api/products", "method": "GET", "expected": "Allowed", "resource_type": "product", "classification": "public", "sensitivity": "low"},
    {"url": "/api/search", "method": "GET", "expected": "Allowed", "resource_type": "search", "classification": "public", "sensitivity": "low"},
    {"url": "/api/user/profile", "method": "GET", "expected": "User Only", "resource_type": "user", "classification": "internal", "sensitivity": "medium"},
    {"url": "/api/categories", "method": "GET", "expected": "Allowed", "resource_type": "category", "classification": "public", "sensitivity": "low"},
    {"url": "/api/cart/{id}", "method": "GET", "expected": "Owner Only", "resource_type": "cart", "classification": "internal", "sensitivity": "medium"},
    {"url": "/api/cart/{id}/add", "method": "POST", "expected": "Owner Only", "resource_type": "cart", "classification": "internal", "sensitivity": "medium"},
]

# Create attack patterns - sequences of requests that form an attack
attack_patterns = [
    # Privilege escalation attempt pattern
    [
        {"type": "benign", "count": 3},  # Some normal activity
        {"type": "auth", "action": "login"},  # Login
        {"type": "benign", "count": 2},  # More normal activity
        {"type": "attack", "count": 1},  # Attack attempt
    ],
    # Credential stuffing pattern
    [
        {"type": "auth", "action": "failed_login", "count": 5},  # Multiple failed logins
        {"type": "auth", "action": "login"},  # Successful login
        {"type": "attack", "count": 2},  # Attack attempts
    ],
    # Reconnaissance pattern
    [
        {"type": "benign", "count": 1},  # Start with something innocent
        {"type": "scan", "count": 8},  # Multiple endpoints to map the API
        {"type": "attack", "count": 1},  # Targeted attack
    ],
]

# Role-based behavior profiles
role_behaviors = {
    "Guest": {
        "common_resources": ["/api/products", "/api/search", "/api/categories"],
        "uncommon_resources": ["/api/user", "/api/payments", "/api/orders"],
        "forbidden_resources": ["/api/admin", "/api/transactions", "/hidden_admin_portal"],
        "typical_methods": ["GET"],
        "atypical_methods": ["POST", "PUT", "DELETE"],
        "session_length": (5, 30),  # min and max in minutes
        "requests_per_minute": (1, 5)
    },
    "User": {
        "common_resources": ["/api/products", "/api/search", "/api/user/profile", "/api/cart"],
        "uncommon_resources": ["/api/account/change-password"],
        "forbidden_resources": ["/api/admin", "/api/transactions", "/hidden_admin_portal", "/api/user/role"],
        "typical_methods": ["GET", "POST"],
        "atypical_methods": ["PUT", "DELETE"],
        "session_length": (10, 60),
        "requests_per_minute": (2, 8)
    },
    "Admin": {
        "common_resources": ["/api/products", "/api/user", "/api/orders", "/api/transactions"],
        "uncommon_resources": ["/api/account/delete", "/hidden_admin_portal"],
        "forbidden_resources": [],
        "typical_methods": ["GET", "POST", "PUT", "DELETE"],
        "atypical_methods": [],
        "session_length": (20, 120),
        "requests_per_minute": (3, 15)
    },
    "Malicious": {
        "session_length": (5, 180),
        "requests_per_minute": (1, 30),
        "attack_probability": 0.7
    }
}

def generate_test_cases(n=25, simulation_mode="mixed"):
    """
    Generate test cases with more realistic patterns based on simulation mode
    
    Modes:
    - normal: Mostly legitimate traffic with proper access patterns
    - attack: Focused on attack scenarios
    - mixed: A combination of both with occasional attacks
    - pattern: Follow specific attack patterns
    """
    test_cases = []
    
    # Determine the mix of traffic based on simulation mode
    if simulation_mode == "normal":
        legitimate_ratio = 0.95
    elif simulation_mode == "attack":
        legitimate_ratio = 0.5
    elif simulation_mode == "mixed":
        legitimate_ratio = 0.5
    elif simulation_mode == "pattern":
        # For pattern mode, we'll generate sequences according to attack_patterns
        return generate_pattern_test_cases(n)
    
    # Distribution of user roles based on simulation mode
    if simulation_mode == "normal":
        role_weights = {"Guest": 0.3, "User": 0.6, "Admin": 0.1, "Malicious": 0.0}
    elif simulation_mode == "attack":
        role_weights = {"Guest": 0.1, "User": 0.3, "Admin": 0.1, "Malicious": 0.5}
    else:  # mixed
        role_weights = {"Guest": 0.2, "User": 0.5, "Admin": 0.1, "Malicious": 0.2}
    
    roles = [role for role in ROLES]
    role_probabilities = [role_weights[role] for role in roles]
    
    # Normalize probabilities to ensure they sum to 1
    total_prob = sum(role_probabilities)
    if total_prob == 0:  # Avoid division by zero
        role_probabilities = [0.25, 0.25, 0.25, 0.25]  # Equal probability as fallback
    else:
        role_probabilities = [p/total_prob for p in role_probabilities]
    
    for _ in range(n):
        # Select role based on weights
        role = np.random.choice(roles, p=role_probabilities)
        
        # Generate user ID - maintaining consistency for the same user
        user_id = random.randint(1, 50)
        
        # Determine if this request will be legitimate or an attack attempt
        is_legitimate = random.random() < legitimate_ratio
        
        # For malicious actors, most requests are attack attempts
        if role == "Malicious":
            is_legitimate = random.random() > role_behaviors["Malicious"]["attack_probability"]
        
        # Select endpoint based on legitimacy and role
        if is_legitimate:
            # Choose from appropriate endpoints based on role behavior
            if role in ["Guest", "User", "Admin"]:
                # Higher probability for common resources
                if random.random() < 0.7:
                    resource_pool = [
                        ep for ep in benign_endpoints 
                        if any(common in ep["url"] for common in role_behaviors[role]["common_resources"])
                    ]
                else:
                    resource_pool = [
                        ep for ep in benign_endpoints + attack_endpoints
                        if not any(forbidden in ep["url"] for forbidden in role_behaviors[role].get("forbidden_resources", []))
                    ]
                
                if not resource_pool:
                    resource_pool = benign_endpoints
                
                endpoint = random.choice(resource_pool)
            else:
                # Malicious users occasionally make legitimate requests for cover
                endpoint = random.choice(benign_endpoints)
        else:
            # For attack attempts, select from attack endpoints
            endpoint = random.choice(attack_endpoints)
        
        # Generate or reuse token
        if user_id in user_device_fingerprints:
            # Reuse existing token for the same user to maintain session consistency
            if role != "Malicious":
                token = f"existing_token_{user_id}"
                # 5% chance to use a tampered token for non-malicious users (to simulate compromised tokens)
                token_validity = "Tampered" if random.random() < 0.05 else "Valid"
            else:
                token, _ = generate_jwt(role, user_id)
                token_validity = "Tampered"  # Malicious users typically have tampered tokens
        else:
            # Generate new token for new user
            token, _ = generate_jwt(role, user_id)
            token_validity = "Valid" if role != "Malicious" else "Tampered"
            
            # Generate and store fingerprint for this user
            fingerprint, device_data = generate_device_fingerprint()
            user_device_fingerprints[user_id] = {
                "fingerprint": fingerprint,
                "device_data": device_data
            }
        
        # Prepare the URL with dynamic parameters
        url = endpoint["url"]
        if "{id}" in url:
            # For owner resources, use the user's ID most of the time
            if "Owner" in endpoint["expected"] and random.random() < 0.8:
                url = url.replace("{id}", str(user_id))
            else:
                # If it's an attack attempt, try to access another user's resource
                if not is_legitimate:
                    target_id = random.choice([i for i in range(1, 51) if i != user_id])
                    url = url.replace("{id}", str(target_id))
                else:
                    # For legitimate requests, mostly access own resources with occasionally others for admins
                    if role == "Admin" and random.random() < 0.4:
                        url = url.replace("{id}", str(random.randint(1, 50)))
                    else:
                        url = url.replace("{id}", str(user_id))
        
        # Generate appropriate HTTP method
        method = endpoint["method"]
        if role in ["Guest", "User", "Admin"] and method in role_behaviors[role].get("atypical_methods", []):
            # If this method is atypical for this role and it's a legitimate request,
            # occasionally use a more appropriate method
            if is_legitimate and random.random() < 0.7:
                method = random.choice(role_behaviors[role].get("typical_methods", ["GET"]))
        
        # Determine login status
        login_status = "Guest" if role == "Guest" else "Logged In"
        
        # Set authentication method - more realistic distribution
        if role == "Guest":
            auth_method = random.choices(["None", "Basic", "OAuth"], weights=[0.5, 0.2, 0.3])[0]
        else:
            auth_method = random.choices(["JWT", "OAuth", "Basic"], weights=[0.6, 0.3, 0.1])[0]
            
        # Generate consistent IP address and geolocation for the user
        if user_id in user_geolocation:
            # 90% chance to use the same IP for the same user
            if random.random() < 0.9 and user_ip_addresses[user_id]:  # Check if set is not empty
                ip_address = random.choice(list(user_ip_addresses[user_id]))
                geo_data = user_geolocation[user_id].get(ip_address)
                if geo_data is None:  # If geolocation data is missing, generate it
                    geo_data = generate_geo_data(ip_address)
                    user_geolocation[user_id][ip_address] = geo_data
            else:
                # Occasionally use a different IP (mobile users, VPN, etc.)
                ip_address = fake.ipv4()
                geo_data = generate_geo_data(ip_address)
                with ip_addresses_lock:
                    user_ip_addresses[user_id].add(ip_address)
                    user_geolocation[user_id][ip_address] = geo_data
        else:
            ip_address = fake.ipv4()
            geo_data = generate_geo_data(ip_address)
            with ip_addresses_lock:
                user_ip_addresses[user_id].add(ip_address)
                user_geolocation[user_id] = {ip_address: geo_data}
        
        test_cases.append({
            "url": url,
            "method": method,
            "expected": endpoint["expected"],
            "role": role,
            "token": token,
            "resource_type": endpoint["resource_type"],
            "classification": endpoint["classification"],
            "user_id": user_id,
            "auth_method": auth_method,
            "token_validity": token_validity,
            "login_status": login_status,
            "ip_address": ip_address,
            "geo_data": geo_data,
            "device_fingerprint": user_device_fingerprints[user_id]["fingerprint"],
            "device_data": user_device_fingerprints[user_id]["device_data"],
            "is_legitimate": is_legitimate,
            "sensitivity": endpoint["sensitivity"]
        })
    
    return test_cases

def generate_pattern_test_cases(n=25):
    """Generate test cases that follow specific attack patterns"""
    test_cases = []
    remaining = n
    
    while remaining > 0:
        # Select a random attack pattern
        pattern = random.choice(attack_patterns)
        
        # Calculate how many total requests this pattern will generate
        pattern_size = sum(step.get("count", 1) for step in pattern)
        
        # Skip this pattern if it would exceed the remaining count
        if pattern_size > remaining:
            # If all patterns are too large, take a subset of a random pattern
            if all(sum(step.get("count", 1) for step in p) > remaining for p in attack_patterns):
                # Create a smaller version of the pattern that fits
                modified_pattern = []
                total = 0
                for step in pattern:
                    step_count = min(step.get("count", 1), remaining - total)
                    if step_count > 0:
                        modified_pattern.append({**step, "count": step_count})
                        total += step_count
                    if total >= remaining:
                        break
                pattern = modified_pattern
            else:
                continue  # Try another pattern
        
        # Create a user for this pattern
        user_id = random.randint(1, 50)
        role = random.choice(["User", "Malicious"])
        token, _ = generate_jwt(role, user_id)
        token_validity = "Valid" if role != "Malicious" else "Tampered"
        
        # Generate device fingerprint if not exists
        if user_id not in user_device_fingerprints:
            fingerprint, device_data = generate_device_fingerprint()
            user_device_fingerprints[user_id] = {
                "fingerprint": fingerprint,
                "device_data": device_data
            }
        
        # Generate IP and geo data if not exists
        if user_id not in user_geolocation:
            ip_address = fake.ipv4()
            geo_data = generate_geo_data(ip_address)
            with ip_addresses_lock:
                user_ip_addresses[user_id].add(ip_address)
                user_geolocation[user_id] = {ip_address: geo_data}
        else:
            if user_ip_addresses[user_id]:  # Check if set is not empty
                ip_address = random.choice(list(user_ip_addresses[user_id]))
                geo_data = user_geolocation[user_id].get(ip_address)
                if geo_data is None:  # If geolocation data is missing, generate it
                    geo_data = generate_geo_data(ip_address)
                    user_geolocation[user_id][ip_address] = geo_data
            else:
                ip_address = fake.ipv4()
                geo_data = generate_geo_data(ip_address)
                with ip_addresses_lock:
                    user_ip_addresses[user_id].add(ip_address)
                    user_geolocation[user_id][ip_address] = geo_data
        
        # Process each step in the pattern
        pattern_test_cases = []
        
        for step in pattern:
            step_type = step["type"]
            count = min(step.get("count", 1), remaining)  # Ensure we don't exceed remaining
            
            for _ in range(count):
                if remaining <= 0:
                    break
                    
                if step_type == "benign":
                    endpoint = random.choice(benign_endpoints)
                    is_legitimate = True
                elif step_type == "attack":
                    endpoint = random.choice(attack_endpoints)
                    is_legitimate = False
                elif step_type == "scan":
                    # Scanning different endpoints
                    all_endpoints = benign_endpoints + attack_endpoints
                    endpoint = random.choice(all_endpoints)
                    is_legitimate = True
                elif step_type == "auth":
                    # Authentication related endpoints
                    auth_endpoint = {
                        "url": "/api/login", 
                        "method": "POST", 
                        "expected": "Allowed",
                        "resource_type": "auth", 
                        "classification": "public", 
                        "sensitivity": "medium"
                    }
                    endpoint = auth_endpoint
                    action = step.get("action", "login")
                    is_legitimate = action == "login"  # True for login, False for failed_login
                
                # Prepare URL with dynamic parameters
                url = endpoint["url"]
                if "{id}" in url:
                    if is_legitimate and "Owner" in endpoint["expected"]:
                        url = url.replace("{id}", str(user_id))
                    else:
                        target_id = random.choice([i for i in range(1, 51) if i != user_id])
                        url = url.replace("{id}", str(target_id))
                
                login_status = "Guest" if role == "Guest" else "Logged In"
                auth_method = "JWT" if role != "Guest" else "None"
                
                test_case = {
                    "url": url,
                    "method": endpoint["method"],
                    "expected": endpoint["expected"],
                    "role": role,
                    "token": token,
                    "resource_type": endpoint["resource_type"],
                    "classification": endpoint["classification"],
                    "user_id": user_id,
                    "auth_method": auth_method,
                    "token_validity": token_validity,
                    "login_status": login_status,
                    "ip_address": ip_address,
                    "geo_data": geo_data,
                    "device_fingerprint": user_device_fingerprints[user_id]["fingerprint"],
                    "device_data": user_device_fingerprints[user_id]["device_data"],
                    "is_legitimate": is_legitimate,
                    "sensitivity": endpoint["sensitivity"],
                    "pattern_step": step_type
                }
                
                pattern_test_cases.append(test_case)
                remaining -= 1
                
                if remaining <= 0:
                    break
        
        # Add all test cases from this pattern
        test_cases.extend(pattern_test_cases)
    
    return test_cases

def send_request(base_url, token, test_case):
    """Simulate sending an HTTP request and getting a response"""
    user_agent = fake.user_agent()
    ip_address = test_case["ip_address"]
    device_fp = test_case["device_fingerprint"]
    
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": user_agent,
        "X-Forwarded-For": ip_address,
        "Referer": random.choice([fake.url(), ""]),
        "X-Device-Fingerprint": device_fp
    }
    
    # In a real implementation, this would make an actual HTTP request
    # For simulation, we'll create a mock response
    if test_case["is_legitimate"]:
        # For legitimate requests, behavior depends on role
        if test_case["role"] == "Admin":
            # Admins generally get access
            status_code = 200
            response_body = json.dumps({"status": "success", "data": {"id": test_case["user_id"]}})
        elif test_case["role"] == "User":
            # Users get access to their own resources and public ones
            if "Owner" in test_case["expected"] and str(test_case["user_id"]) in test_case["url"]:
                status_code = 200
                response_body = json.dumps({"status": "success", "data": {"id": test_case["user_id"]}})
            elif test_case["expected"] == "Allowed" or test_case["classification"] == "public":
                status_code = 200
                response_body = json.dumps({"status": "success", "data": {"id": test_case["user_id"]}})
            else:
                status_code = 403
                response_body = json.dumps({"status": "error", "message": "Access denied"})
        else:  # Guest
            # Guests only get access to public resources
            if test_case["expected"] == "Allowed" or test_case["classification"] == "public":
                status_code = 200
                response_body = json.dumps({"status": "success", "data": {"id": 0}})
            else:
                status_code = 401
                response_body = json.dumps({"status": "error", "message": "Authentication required"})
    else:
        # For attack attempts, most should fail but some might succeed (to simulate vulnerabilities)
        if random.random() < 0.05:  # 5% success rate for attacks
            status_code = 200
            response_body = json.dumps({"status": "success", "data": {"id": test_case["user_id"]}})
        else:
            status_code = random.choice([400, 401, 403, 404])
            response_body = json.dumps({"status": "error", "message": "Access denied"})
    
    # Simulate occasional server errors
    if random.random() < 0.02:  # 2% chance of server error
        status_code = 500
        response_body = json.dumps({"status": "error", "message": "Internal server error"})
    
    # Create a mock response object that mimics requests.Response
    class MockResponse:
        def __init__(self, status_code, body):
            self.status_code = status_code
            self.text = body
            self._content = body.encode('utf-8')
            
        def json(self):
            try:
                return json.loads(self.text)
            except json.JSONDecodeError:
                return {"error": "Invalid JSON"}
            
    response = MockResponse(status_code, response_body)
    
    # Update endpoint stats
    endpoint = test_case["url"].split("?")[0]  # Remove query parameters
    with endpoint_failures_lock:
        endpoint_failure_rates[endpoint]["attempts"] += 1
        if status_code >= 400:
            endpoint_failure_rates[endpoint]["failures"] += 1
    
    # Record access time for the user
    current_time = time.time()
    with access_times_lock:
        user_access_times[test_case["user_id"]].append(current_time)
    
    # Record resource access
    resource_type = test_case["resource_type"]
    with resource_access_lock:
        user_resource_access[test_case["user_id"]][resource_type] += 1
        resource_access_frequency[resource_type] += 1
    
    # Calculate additional metrics for analysis
    response_time = random.randint(
        50, 500 if status_code < 500 else 2000
    )  # Simulate slower responses for errors
    
    # Update session data
    session_id = test_case.get("session_id", str(uuid.uuid4()))
    with session_data_lock:
        user_session_data[test_case["user_id"]].append({
            "timestamp": current_time,
            "resource": test_case["url"],
            "method": test_case["method"],
            "status_code": status_code,
            "response_time": response_time,
            "session_id": session_id
        })
    
    return response, user_agent, ip_address, response_time, session_id

def analyze_access(response, expected_access, sensitivity="medium"):
    """Analyze the access result and detect potential BAC issues"""
    if not response:
        return "Error", "No Response"
    
    actual_access = "Allowed" if response.status_code == 200 else "Denied"
    bac_issue = "No"
    
    # Detect BAC issues when access is granted but shouldn't be
    if expected_access != "Allowed" and actual_access == "Allowed":
        # Look for indicators of successful privilege escalation in the response
        try:
            response_data = response.json()
            response_text = str(response_data).lower()
            if "admin" in response_text:
                bac_issue = "Yes (Privilege Escalation)"
            elif "role" in response_text:
                bac_issue = "Yes (Unauthorized Role Access)"
            else:
                bac_issue = "Yes (IDOR)"
        except (json.JSONDecodeError, AttributeError):
            # If we can't parse the response, use the raw text if available
            response_text = getattr(response, 'text', '').lower()
            if "admin" in response_text:
                bac_issue = "Yes (Privilege Escalation)"
            else:
                bac_issue = "Yes (IDOR)"
    
    # For highly sensitive resources, any unexpected success is suspicious
    if sensitivity == "high" and expected_access == "Denied" and actual_access == "Allowed":
        if bac_issue == "No":
            bac_issue = "Yes (Unauthorized Access to Sensitive Resource)"
    
    return actual_access, bac_issue

def calculate_anomaly_score(test_case, response_time):
    """Calculate an anomaly score based on multiple factors"""
    score = 0.0
    
    # Base score on factors that indicate potential attacks
    
    # 1. Authentication factors
    if test_case["token_validity"] == "Tampered":
        score += 0.3
    
    # 2. Role-resource mismatch
    if test_case["role"] == "Guest" and test_case["classification"] == "restricted":
        score += 0.2
    if test_case["role"] == "User" and "Admin Only" in test_case["expected"]:
        score += 0.25
    
    # 3. User behavior anomalies
    user_id = test_case["user_id"]
    
    # Check if user is accessing an unusual resource
    if user_id in user_resource_access:
        resource_type = test_case["resource_type"]
        total_requests = sum(user_resource_access[user_id].values())
        if total_requests > 5:  # Only check if we have enough history
            # FIX: Avoid ZeroDivisionError
            resource_ratio = user_resource_access[user_id][resource_type] / total_requests if total_requests > 0 else 0
            if resource_ratio < 0.1:  # Resource type is rare for this user
                score += 0.15
    
    # 4. Request rate anomalies
    if user_id in user_access_times and len(user_access_times[user_id]) > 5:
        current_time = time.time()
        recent_times = [t for t in user_access_times[user_id] if current_time - t < TIME_WINDOWS["short"]]
        
        if len(recent_times) > 10:  # More than 10 requests in 5 minutes
            score += 0.2
    
    # 5. Response time anomalies (higher score for unusual response times)
    if response_time > 1500:
        score += 0.1
    
    # 6. IP geolocation anomalies
    if user_id in user_ip_addresses and len(user_ip_addresses[user_id]) > 1:
        # Multiple IPs for the same user is suspicious
        score += 0.1
        
    # 7. Sensitivity-based scoring
    if test_case["sensitivity"] == "high":
        score += 0.1
    
    # 8. Method-resource mismatch
    if test_case["method"] in ["DELETE", "PUT"] and test_case["role"] != "Admin":
        score += 0.15
    
    # Add some randomization to avoid deterministic patterns
    score += random.uniform(-0.05, 0.05)
    
    # Ensure score is between 0 and 1
    return max(0.0, min(1.0, score))

def calculate_risk_score(test_case, actual_access, bac_issue, anomaly_score):
    """Calculate a risk score based on the potential impact of the request"""
    score = 0.0
    
    # Base risk on the sensitivity of the resource and access outcome
    sensitivity_weights = {"low": 0.2, "medium": 0.5, "high": 0.8}
    score += sensitivity_weights.get(test_case["sensitivity"], 0.5)
    
    # Higher risk for successful unauthorized access 
    if bac_issue.startswith("Yes"):
        score += 0.4
        
        # Additional risk based on the type of vulnerability
        if "Privilege Escalation" in bac_issue:
            score += 0.3
        elif "IDOR" in bac_issue:
            score += 0.2
    
    # Consider the resource classification
    if test_case["classification"] == "restricted":
        score += 0.2
    
    # Consider the operation type (higher risk for write operations)
    if test_case["method"] in ["POST", "PUT", "DELETE", "PATCH"]:
        score += 0.15
    
    # Factor in the anomaly score
    score += anomaly_score * 0.3
    
    # Add slight randomization
    score += random.uniform(-0.05, 0.05)
    
    # Ensure score is between 0 and 1
    return max(0.0, min(1.0, score))

def extract_request_parameters(url):
    """Extract and analyze request parameters from URL"""
    parsed_url = urlparse(url)
    path_parts = parsed_url.path.strip('/').split('/')
    query_params = parse_qs(parsed_url.query)
    
    parameters = {
        "path_parts": path_parts,
        "query_params": query_params,
        "has_id": any(part.isdigit() for part in path_parts),
        "id_values": [part for part in path_parts if part.isdigit()],
        "param_count": len(query_params)
    }
    
    return parameters

def generate_attack_payload(method, resource_type):
    """Generate realistic attack payloads based on request context"""
    if method == "GET":
        # For GETs, return None most of the time unless it's a scan
        if random.random() < 0.9:
            return "None"
    
    # Common attack patterns for different resource types
    payloads = {
        "user": [
            "' OR 1=1--",
            "admin' --",
            "1; DROP TABLE users--",
            "Blue position necessary stuff people.",
            "{'role' : 'admin'}"
        ],
        "payment": [
            '{"amount":-100}',
            '{"amount":"-100"}',
            "Present use suggest behavior hour peace very.",
            '{"card_number":"null"}'
        ],
        "order": [
            '{"status":"shipped", "payment_received": true}',
            "None",
            "Learn enjoy shake bag worry."
        ],
        "account": [
            "Particularly during speak nation night peace rest.",
            '{"password":"123456", "role":"admin"}',
            "Huge likely indeed happy."
        ],
        "transaction": [
            "None",
            '{"amount": "OR 1=1--"}',
            "Interview include list through."
        ],
        "admin_panel": [
            "admin",
            "admin:admin",
            "Find particular interesting argue."
        ]
    }
    
    # Default payloads if resource type not found
    default_payloads = [
        "None",
        "' OR 1=1--",
        "admin' --",
        '{"admin":true}',
        "Democratic rest threat poor control medical public."
    ]
    
    payload_list = payloads.get(resource_type, default_payloads)
    return random.choice(payload_list)

def analyze_sequence_anomalies(user_id):
    """Analyze request sequences for unusual patterns"""
    # FIX: Use thread lock for shared data access
    with session_data_lock:
        if user_id not in user_session_data or len(user_session_data[user_id]) < 5:
            return 0.0  # Not enough data
            
        sessions = user_session_data[user_id]
        recent_sessions = sorted(sessions, key=lambda x: x["timestamp"], reverse=True)[:10]
    
    # Look for suspicious patterns
    anomaly_score = 0.0
    
    # 1. Rapid failed attempts followed by success
    failed_count = 0
    for i, session in enumerate(recent_sessions):
        if session["status_code"] >= 400:
            failed_count += 1
        elif failed_count >= 3 and i < failed_count + 1:
            # 3+ failures followed by success is suspicious
            anomaly_score += 0.3
            break
    
    # 2. Unusual method sequences
    methods = [s["method"] for s in recent_sessions]
    if methods.count("GET") < len(methods) * 0.5:
        # Fewer than half are GETs (unusual)
        anomaly_score += 0.2
    
    # 3. Resource type transitions
    # FIX: Handle IndexError when splitting resource paths
    resources = []
    for s in recent_sessions:
        parts = s["resource"].split('/')
        if len(parts) > 2:
            resources.append(parts[2])
        else:
            resources.append("unknown")
    
    unique_resources = len(set(resources))
    if unique_resources > 5 and len(resources) < 10:
        # Accessing many different resource types in a short session (scanning behavior)
        anomaly_score += 0.25
    
    return min(anomaly_score, 1.0)

def process_request(request_id, test_case):
    """Process a request and generate all the necessary data"""
    
    # If session_id not provided, generate one
    if "session_id" not in test_case:
        session_id = str(uuid.uuid4())
        test_case["session_id"] = session_id
    else:
        session_id = test_case["session_id"]
    
    # Generate timestamp with slight increments for sequential ordering
    timestamp = datetime.datetime.now().isoformat()
    
    # Generate referrer - more realistic patterns
    if random.random() < 0.6:  # 60% chance to have a referrer
        if random.random() < 0.7:  # 70% of referrers are from the same site
            referrer = f"http://{random.choice(list(BASE_URLS.values())).replace('http://', '')}/some/page"
        else:
            referrer = fake.url()
    else:
        referrer = ""
    
    # Send request and get response
    response, user_agent, ip_address, response_time, session_id = send_request(
        BASE_URLS['juice_shop'], test_case['token'], test_case
    )
    
    # Get response code
    response_code = response.status_code if response else "No Response"
    
    # Analyze the access result
    actual_access, bac_issue = analyze_access(response, test_case["expected"], test_case["sensitivity"])
    
    # Extract request parameters
    request_params = extract_request_parameters(test_case["url"])
    
    # Generate attack payload if applicable
    attack_payload = generate_attack_payload(test_case["method"], test_case["resource_type"])
    
    # Calculate anomaly score
    anomaly_score = calculate_anomaly_score(test_case, response_time)
    
    # Add sequence analysis
    sequence_anomaly = analyze_sequence_anomalies(test_case["user_id"])
    anomaly_score = (anomaly_score + sequence_anomaly) / 2
    anomaly_score = round(anomaly_score, 4)
    
    # Determine if an attack was detected
    attack_detected = 1 if "Yes" in bac_issue or anomaly_score > 0.75 else 0
    
    # Calculate risk score
    risk_score = calculate_risk_score(test_case, actual_access, bac_issue, anomaly_score)
    risk_score = round(risk_score, 4)
    
    # Generate additional features for ML training
    
    # 1. Time-based features
    current_time = datetime.datetime.now()
    hour_of_day = current_time.hour
    day_of_week = current_time.weekday()
    is_weekend = 1 if day_of_week >= 5 else 0
    is_business_hours = 1 if 9 <= hour_of_day <= 17 and not is_weekend else 0
    
    # 2. User history features
    user_id = test_case["user_id"]
    # FIX: Use thread lock for user_session_data access
    with session_data_lock:
        recent_failures = 0
        requests_last_hour = 0
        avg_request_time = 0
        
        if user_id in user_session_data:
            current_timestamp = time.time()
            user_history = user_session_data[user_id]
            
            # Count recent failures
            recent_failures = sum(1 for s in user_history 
                                if s["status_code"] >= 400 and 
                                current_timestamp - s["timestamp"] < TIME_WINDOWS["short"])
            
            # Count requests in last hour
            requests_last_hour = sum(1 for s in user_history 
                                    if current_timestamp - s["timestamp"] < TIME_WINDOWS["medium"])
            
            # Calculate average response time
            if user_history:
                avg_request_time = sum(s["response_time"] for s in user_history) / len(user_history)
    
    # 3. Resource access pattern features
    resource_type = test_case["resource_type"]
    # FIX: Use thread lock for resource_access_frequency
    with resource_access_lock:
        total_resources = sum(resource_access_frequency.values())
        resource_popularity = resource_access_frequency.get(resource_type, 0) / max(total_resources, 1)
    
    # Core dataset fields - same as your original for compatibility
    core_data = [
        request_id, timestamp, test_case["user_id"], test_case["role"], test_case["url"], test_case["method"],
        referrer, user_agent, ip_address, session_id, test_case["auth_method"], test_case["token_validity"], 
        test_case["login_status"], test_case["classification"], test_case["resource_type"], response_code, 
        test_case["expected"], actual_access, bac_issue, attack_payload, anomaly_score,
        attack_detected, risk_score, response_time
    ]
    
    # Extended features for ML training - can be written to a separate file
    extended_features = {
        "hour_of_day": hour_of_day,
        "day_of_week": day_of_week, 
        "is_weekend": is_weekend,
        "is_business_hours": is_business_hours,
        "recent_failures": recent_failures,
        "requests_last_hour": requests_last_hour,
        "avg_request_time": avg_request_time,
        "resource_popularity": resource_popularity,
        "params_count": request_params["param_count"],
        "has_id_parameter": request_params["has_id"],
        "sequence_anomaly_score": sequence_anomaly,
        "device_fingerprint": test_case["device_fingerprint"],
        "geo_continent": test_case["geo_data"]["continent"],
        "geo_country": test_case["geo_data"]["country"],
        "path_depth": len(request_params["path_parts"]),
        "is_sensitive_resource": 1 if test_case["sensitivity"] == "high" else 0,
        "is_legitimate_request": 1 if test_case.get("is_legitimate", True) else 0
    }
    
    return core_data, extended_features

# FIX: Define extended_features_file at the module level
extended_features_file = "ml_training_features.csv"

def run_bac_tests(batch_size=1000, simulation_mode="mixed"):
    """Run BAC testing with enhanced features and simulation modes"""
    test_cases = generate_test_cases(batch_size, simulation_mode)
    
    # Prepare files
    with open(bac_results_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        if file.tell() == 0:
            writer.writerow([
                "request_id", "timestamp", "user_id", "user_role", "requested_resource", "request_method",
                "referrer", "user_agent", "ip_address", "session_id", "auth_method", "auth_token_validity",
                "login_status", "resource_classification", "resource_type", "response_code", "expected_access",
                "actual_access_granted", "vulnerability_type", "attack_payload", "anomaly_score",
                "attack_detected", "risk_score", "response_time_ms"
            ])
    
    # Create extended features file
    with open(extended_features_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        if file.tell() == 0:
            writer.writerow([
                "request_id", "user_id", "hour_of_day", "day_of_week", "is_weekend",
                "is_business_hours", "recent_failures", "requests_last_hour", "avg_request_time",
                "resource_popularity", "params_count", "has_id_parameter", "sequence_anomaly_score",
                "device_fingerprint", "geo_continent", "geo_country", "path_depth",
                "is_sensitive_resource", "is_legitimate_request", "attack_detected"
            ])
    
    # Process requests with concurrent execution
    results = []
    extended_results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(process_request, i, test_case) for i, test_case in enumerate(test_cases)]
        
        # FIX: Properly handle futures results
        for future in concurrent.futures.as_completed(futures):
            try:
                core_data, extended_features = future.result()
                results.append(core_data)
                
                # Add request_id and user_id to extended features
                extended_row = [core_data[0], core_data[2]]  # request_id, user_id
                
                # FIX: Safely access extended_features dictionary
                extended_row.extend([
                    extended_features.get("hour_of_day", 0),
                    extended_features.get("day_of_week", 0),
                    extended_features.get("is_weekend", 0),
                    extended_features.get("is_business_hours", 0),
                    extended_features.get("recent_failures", 0),
                    extended_features.get("requests_last_hour", 0),
                    extended_features.get("avg_request_time", 0),
                    extended_features.get("resource_popularity", 0),
                    extended_features.get("params_count", 0),
                    extended_features.get("has_id_parameter", 0),
                    extended_features.get("sequence_anomaly_score", 0),
                    extended_features.get("device_fingerprint", ""),
                    extended_features.get("geo_continent", ""),
                    extended_features.get("geo_country", ""),
                    extended_features.get("path_depth", 0),
                    extended_features.get("is_sensitive_resource", 0),
                    extended_features.get("is_legitimate_request", 1),
                    core_data[21]  # attack_detected
                ])
                extended_results.append(extended_row)
            except Exception as e:
                print(f"Error processing request: {e}")
    
    # In the run_bac_tests function:
    with open(bac_results_file, mode='a', newline='') as file:
    	writer = csv.writer(file)
    	writer.writerows(results)
        
    with open(extended_features_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(extended_results)
    
    print(f"✅ Enhanced BAC testing completed with {simulation_mode} mode.")
    
    # Save user behavior profiles periodically
    if random.random() < 0.2:  # 20% chance to save profiles each batch
        save_behavior_profiles()

def save_behavior_profiles():
    """Save user behavior profiles for future analysis"""
    profiles = {}
    
    # FIX: Use thread locks for shared data structures
    with session_data_lock, resource_access_lock, access_times_lock, ip_addresses_lock:
        for user_id in user_resource_access:
            # Skip users with very little data
            if len(user_session_data.get(user_id, [])) < 5:
                continue
                
            resources = user_resource_access[user_id]
            total_requests = sum(resources.values())
            
            # FIX: Avoid division by zero
            if total_requests == 0:
                continue
            
            # Calculate access patterns
            resource_distribution = {resource: count/total_requests for resource, count in resources.items()}
            
            # Calculate time patterns
            access_times = user_access_times.get(user_id, [])
            hour_distribution = [0] * 24
            
            for timestamp in access_times:
                hour = datetime.datetime.fromtimestamp(timestamp).hour
                hour_distribution[hour] += 1
                
            if access_times:
                hour_distribution = [count / len(access_times) for count in hour_distribution]
            
            # Calculate session metrics
            sessions = user_session_data.get(user_id, [])
            avg_response_time = sum(s["response_time"] for s in sessions) / max(len(sessions), 1)
            error_rate = sum(1 for s in sessions if s["status_code"] >= 400) / max(len(sessions), 1)
            
            # Store profile
            profiles[user_id] = {
                "resource_distribution": resource_distribution,
                "hour_distribution": hour_distribution,
                "avg_response_time": avg_response_time,
                "error_rate": error_rate,
                "ip_addresses": list(user_ip_addresses.get(user_id, set())),
                "device_fingerprint": user_device_fingerprints.get(user_id, {}).get("fingerprint", ""),
                "request_count": len(sessions)
            }
    
    # Save to file
    with open(user_behavior_file, 'w') as f:
        json.dump(profiles, f, indent=2)
    
    # Save resource access patterns
    # FIX: Use thread locks for shared data
    with resource_access_lock, endpoint_failures_lock:
        total_resources = sum(resource_access_frequency.values())
        # FIX: Avoid division by zero
        if total_resources > 0:
            resource_patterns = {
                "global_popularity": {r: count/total_resources 
                                    for r, count in resource_access_frequency.items()},
                "failure_rates": {endpoint: data["failures"]/max(data["attempts"], 1) 
                                for endpoint, data in endpoint_failure_rates.items()}
            }
            
            with open(resource_access_patterns_file, 'w') as f:
                json.dump(resource_patterns, f, indent=2)
    
    print("✅ Behavior profiles saved.")

def generate_ml_training_dataset(normal_ratio=0.5, attack_ratio=0.5, size=1000):
    """Generate a balanced dataset specifically for training ML models"""
    print(f"Generating ML training dataset with {size} samples...")
    
    # Generate mostly normal traffic
    print("Generating normal traffic samples...")
    run_bac_tests(int(size * normal_ratio), "normal")
    
    # Generate attack traffic
    print("Generating attack traffic samples...")
    run_bac_tests(int(size * attack_ratio * 0.5), "attack")
    
    # Generate pattern-based attack traffic
    print("Generating pattern-based attack samples...")
    run_bac_tests(int(size * attack_ratio * 0.5), "pattern")
    
    print("✅ ML training dataset generation complete!")

def prepare_ml_features():
    """Prepare and transform features for ML model training"""
    print("Preparing ML features from collected data...")
    
    # Load data
    try:
        # FIX: Use the global variable
        df = pd.read_csv(extended_features_file)
        print(f"Loaded {len(df)} samples")
        
        # Feature engineering
        # 1. Time-based features
        df['hour_sin'] = np.sin(2 * np.pi * df['hour_of_day'] / 24)
        df['hour_cos'] = np.cos(2 * np.pi * df['hour_of_day'] / 24)
        df['day_sin'] = np.sin(2 * np.pi * df['day_of_week'] / 7)
        df['day_cos'] = np.cos(2 * np.pi * df['day_of_week'] / 7)
        
        # 2. Categorical encoding for geographical features
        # FIX: Handle missing or empty values
        df['geo_continent'] = df['geo_continent'].fillna('Unknown')
        df['geo_country'] = df['geo_country'].fillna('Unknown')
        
        geo_continent_dummies = pd.get_dummies(df['geo_continent'], prefix='continent')
        geo_country_dummies = pd.get_dummies(df['geo_country'], prefix='country')
        
        # Limit country features to avoid too many dimensions
        top_countries = geo_country_dummies.sum().sort_values(ascending=False).head(20).index
        geo_country_dummies = geo_country_dummies[top_countries]
        
        # 3. Combine all features
        # FIX: Safely drop columns that might not exist
        columns_to_drop = ['geo_continent', 'geo_country', 'device_fingerprint', 'request_id']
        existing_columns = [col for col in columns_to_drop if col in df.columns]
        
        feature_df = pd.concat([
            df.drop(existing_columns, axis=1),
            geo_continent_dummies,
            geo_country_dummies
        ], axis=1)
        
        # Save processed features
        feature_df.to_csv("ml_processed_features.csv", index=False)
        print("✅ ML features prepared and saved to ml_processed_features.csv")
        
        # Display class distribution
        attack_count = feature_df['attack_detected'].sum()
        total = len(feature_df)
        print(f"Class distribution:")
        print(f"- Normal requests: {total - attack_count} ({(total - attack_count) / total:.2%})")
        print(f"- Attack requests: {attack_count} ({attack_count / total:.2%})")
        
    except Exception as e:
        print(f"Error preparing ML features: {e}")

if __name__ == "__main__":
    try:
        print("Starting enhanced BAC testing for 1 million rows...")
        
        # Target count
        total_target = 1000000
        rows_generated = 0
        batch_size = 20000  # Increased batch size for efficiency
        
        # Progress tracking
        start_time = time.time()
        last_progress_report = start_time
        
        # Phase distribution (modify percentages as needed)
        normal_percentage = 0.40  # 40% normal traffic
        mixed_percentage = 0.10   # 10% mixed traffic
        pattern_percentage = 0.25 # 25% pattern-based attacks
        attack_percentage = 0.25  # 25% direct attacks
        
        print(f"Generating data with distribution: {normal_percentage:.0%} normal, {mixed_percentage:.0%} mixed, {pattern_percentage:.0%} pattern attacks, {attack_percentage:.0%} direct attacks")
        
        # Generate data in batches until we reach target
        while rows_generated < total_target:
            # Determine batch type based on our target distribution
            rand_val = random.random()
            
            # Calculate remaining counts needed
            remaining = total_target - rows_generated
            current_batch = min(batch_size, remaining)
            
            if rand_val < normal_percentage:
                mode = "normal"
            elif rand_val < normal_percentage + mixed_percentage:
                mode = "mixed"
            elif rand_val < normal_percentage + mixed_percentage + pattern_percentage:
                mode = "pattern"
            else:
                mode = "attack"
                
            # Generate batch
            print(f"Generating batch of {current_batch} rows using '{mode}' mode...")
            run_bac_tests(current_batch, mode)
            
            # Update progress
            rows_generated += current_batch
            current_time = time.time()
            
            # Show progress every minute
            if current_time - last_progress_report >= 60:
                elapsed = current_time - start_time
                rows_per_second = rows_generated / elapsed
                estimated_total = elapsed * (total_target / rows_generated)
                remaining_time = estimated_total - elapsed
                
                print(f"Progress: {rows_generated:,}/{total_target:,} rows ({rows_generated/total_target:.1%})")
                print(f"Speed: {rows_per_second:.1f} rows/second")
                print(f"Elapsed: {elapsed/3600:.1f} hours, Estimated remaining: {remaining_time/3600:.1f} hours")
                
                last_progress_report = current_time
        
        print(f"✅ Generated {rows_generated:,} total rows!")
        
        print("Preparing ML features...")
        prepare_ml_features()
        
        print("✅ Script execution completed successfully!")
        total_time = (time.time() - start_time) / 3600
        print(f"Total execution time: {total_time:.2f} hours")
        
    except Exception as e:
        print(f"❌ Error during execution: {e}")
