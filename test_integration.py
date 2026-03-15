#!/usr/bin/env python
"""
FREELANCER PLATFORM - COMPLETE INTEGRATION TEST
Tests Frontend ↔ Backend ↔ Database Connection
Run this after starting MongoDB, Backend, and checking Frontend
"""

import subprocess
import requests
import json
import time
from datetime import datetime

# Colors for terminal output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

# Configuration
BACKEND_URL = "http://localhost:8000"
API_BASE_URL = f"{BACKEND_URL}/api"
FRONTEND_URL = "http://localhost:3000"

def print_header(text):
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}{text.center(60)}{RESET}")
    print(f"{BLUE}{'='*60}{RESET}\n")

def print_success(text):
    print(f"{GREEN}✅ {text}{RESET}")

def print_error(text):
    print(f"{RED}❌ {text}{RESET}")

def print_warning(text):
    print(f"{YELLOW}⚠️  {text}{RESET}")

def print_info(text):
    print(f"{BLUE}ℹ️  {text}{RESET}")

def test_mongodb_connection():
    """Test MongoDB connection"""
    print_header("Testing MongoDB Connection")
    
    try:
        import mongoengine
        mongoengine.disconnect()
        mongoengine.connect(
            db='freelancer_db',
            host='mongodb://localhost:27017',
            retryWrites=False,
            connect=True,
            serverSelectionTimeoutMS=5000
        )
        print_success("MongoDB is running and accessible")
        print_info(f"Database: freelancer_db")
        print_info(f"Host: localhost:27017")
        return True
    except Exception as e:
        print_error(f"MongoDB connection failed: {str(e)}")
        print_warning("Make sure MongoDB is running!")
        return False

def test_backend_is_running():
    """Test if backend server is running"""
    print_header("Testing Backend Server")
    
    try:
        response = requests.get(BACKEND_URL, timeout=5)
        if response.status_code == 200 or response.status_code == 301:
            print_success(f"Backend server is running on {BACKEND_URL}")
            return True
    except requests.exceptions.ConnectionError:
        print_error(f"Backend server is NOT running on {BACKEND_URL}")
        print_warning("Run: python manage.py runserver")
        return False
    except Exception as e:
        print_error(f"Error connecting to backend: {str(e)}")
        return False

def test_cors_configuration():
    """Test CORS configuration"""
    print_header("Testing CORS Configuration")
    
    try:
        headers = {'Origin': FRONTEND_URL}
        response = requests.options(f"{API_BASE_URL}/jobs/", headers=headers, timeout=5)
        
        if 'Access-Control-Allow-Origin' in response.headers:
            print_success("CORS is properly configured")
            print_info(f"Allowed Origin: {response.headers.get('Access-Control-Allow-Origin')}")
            return True
        else:
            print_warning("CORS headers not found in response")
            return False
    except Exception as e:
        print_error(f"CORS test failed: {str(e)}")
        return False

def test_user_registration():
    """Test user registration endpoint"""
    print_header("Testing User Registration")
    
    try:
        test_email = f"test_{int(time.time())}@example.com"
        payload = {
            "email": test_email,
            "password": "testpass123",
            "role": "freelancer",
            "full_name": "Test User"
        }
        
        response = requests.post(
            f"{API_BASE_URL}/accounts/register/",
            json=payload,
            timeout=10
        )
        
        if response.status_code == 201 or response.status_code == 200:
            data = response.json()
            if 'access' in data and 'refresh' in data:
                print_success("User registration working!")
                print_info(f"Email: {test_email}")
                print_info(f"Access Token: {data['access'][:50]}...")
                return True, data['access'], test_email
        else:
            print_error(f"Registration failed: {response.status_code}")
            print_info(f"Response: {response.text}")
            return False, None, None
    except Exception as e:
        print_error(f"Registration test failed: {str(e)}")
        return False, None, None

def test_user_login(email, password="testpass123"):
    """Test user login endpoint"""
    print_header("Testing User Login")
    
    try:
        payload = {
            "email": email,
            "password": password
        }
        
        response = requests.post(
            f"{API_BASE_URL}/token/",
            json=payload,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if 'access' in data and 'refresh' in data:
                print_success("User login working!")
                print_info(f"Email: {email}")
                print_info(f"Access Token: {data['access'][:50]}...")
                return True, data['access']
        else:
            print_error(f"Login failed: {response.status_code}")
            print_info(f"Response: {response.text}")
            return False, None
    except Exception as e:
        print_error(f"Login test failed: {str(e)}")
        return False, None

def test_protected_endpoint(access_token):
    """Test protected endpoint with JWT token"""
    print_header("Testing Protected Endpoint")
    
    try:
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        
        response = requests.get(
            f"{API_BASE_URL}/jobs/",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            print_success("Protected endpoint is working!")
            print_info(f"Jobs endpoint accessible")
            print_info(f"Response type: {type(data)}")
            return True
        else:
            print_error(f"Protected endpoint failed: {response.status_code}")
            print_info(f"Response: {response.text}")
            return False
    except Exception as e:
        print_error(f"Protected endpoint test failed: {str(e)}")
        return False

def test_database_models():
    """Test if all database models are accessible"""
    print_header("Testing Database Models")
    
    try:
        import os
        import django
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'FreelancerBackend.settings')
        django.setup()
        
        from accounts.models import CustomUser
        from profiles.models import Profile
        from jobs.models import Job
        from proposals.models import Proposal
        from payments.models import Transaction, Payout
        from chat.models import Conversation, Message
        from notifications.models import Notification, NotificationPreference
        
        models = [
            ('CustomUser', CustomUser),
            ('Profile', Profile),
            ('Job', Job),
            ('Proposal', Proposal),
            ('Transaction', Transaction),
            ('Payout', Payout),
            ('Conversation', Conversation),
            ('Message', Message),
            ('Notification', Notification),
            ('NotificationPreference', NotificationPreference),
        ]
        
        for model_name, model_class in models:
            try:
                count = model_class.objects.count()
                print_success(f"{model_name} - Accessible ({count} records)")
            except Exception as e:
                print_error(f"{model_name} - Error: {str(e)[:50]}")
        
        return True
    except Exception as e:
        print_error(f"Model loading failed: {str(e)}")
        return False

def test_frontend_config():
    """Test frontend configuration"""
    print_header("Testing Frontend Configuration")
    
    try:
        # Check .env.local file
        env_file = "freelance-frontend/.env.local"
        with open(env_file, 'r') as f:
            env_content = f.read()
            
        if 'http://localhost:8000/api' in env_content:
            print_success("Frontend .env.local is configured correctly")
            print_info(f"API Base URL set to: http://localhost:8000/api")
            return True
        else:
            print_warning("Frontend .env.local may not have correct API URL")
            return False
    except Exception as e:
        print_error(f"Frontend config check failed: {str(e)}")
        return False

def print_summary(results):
    """Print final summary"""
    print_header("Integration Test Summary")
    
    total_tests = len(results)
    passed_tests = sum(1 for r in results.values() if r)
    failed_tests = total_tests - passed_tests
    
    print(f"Total Tests: {total_tests}")
    print(f"{GREEN}Passed: {passed_tests}{RESET}")
    print(f"{RED}Failed: {failed_tests}{RESET}\n")
    
    print("Test Results:")
    for test_name, result in results.items():
        status = f"{GREEN}✅ PASS{RESET}" if result else f"{RED}❌ FAIL{RESET}"
        print(f"  {test_name:<40} {status}")
    
    if failed_tests == 0:
        print_success("\n🎉 ALL INTEGRATION TESTS PASSED!")
        print_success("Your system is fully connected and ready to use!\n")
    else:
        print_warning(f"\n⚠️  Some tests failed. Please fix the issues above.\n")

def main():
    """Run all tests"""
    print_header("FREELANCER PLATFORM INTEGRATION TEST")
    print_info(f"Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_info(f"Backend URL: {BACKEND_URL}")
    print_info(f"API Base URL: {API_BASE_URL}")
    print_info(f"Frontend URL: {FRONTEND_URL}\n")
    
    results = {}
    
    # Test 1: MongoDB
    results['MongoDB Connection'] = test_mongodb_connection()
    
    # Test 2: Backend Server
    results['Backend Server'] = test_backend_is_running()
    
    # Test 3: CORS
    results['CORS Configuration'] = test_cors_configuration()
    
    # Test 4: Frontend Config
    results['Frontend Configuration'] = test_frontend_config()
    
    # Test 5: Database Models
    results['Database Models'] = test_database_models()
    
    # Test 6: User Registration
    reg_success, access_token, email = test_user_registration()
    results['User Registration'] = reg_success
    
    # Test 7: User Login (if registration worked)
    if reg_success:
        login_success, new_token = test_user_login(email)
        results['User Login'] = login_success
        access_token = new_token
    else:
        results['User Login'] = False
    
    # Test 8: Protected Endpoint
    if access_token:
        results['Protected Endpoint'] = test_protected_endpoint(access_token)
    else:
        results['Protected Endpoint'] = False
    
    # Print summary
    print_summary(results)
    
    return results

if __name__ == "__main__":
    main()
