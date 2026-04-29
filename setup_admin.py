#!/usr/bin/env python
"""
Setup Admin User
Creates or updates an admin user with given credentials
"""

import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'FreelancerBackend.settings')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
django.setup()

from accounts.models import CustomUser
from django.contrib.auth.hashers import make_password

# Admin credentials
ADMIN_EMAIL = "Admin@NX.com"
ADMIN_PASSWORD = "Admin@itadmin"

def setup_admin():
    """Create or update admin user"""
    try:
        # Check if admin already exists
        admin = CustomUser.objects(email=ADMIN_EMAIL).first()
        
        if admin:
            print(f"✅ Admin user '{ADMIN_EMAIL}' already exists. Updating credentials...")
            admin.password = make_password(ADMIN_PASSWORD)
            admin.is_staff = True
            admin.is_superuser = True
            admin.is_active = True
            admin.email_verified = True
            admin.role = "client"  # Admin is a client role
            admin.account_status = "active"
            admin.save()
            print(f"✅ Updated password for {ADMIN_EMAIL}")
        else:
            print(f"✅ Creating admin user '{ADMIN_EMAIL}'...")
            admin = CustomUser(
                email=ADMIN_EMAIL,
                password=make_password(ADMIN_PASSWORD),
                role="client",
                is_staff=True,
                is_superuser=True,
                is_active=True,
                email_verified=True,
                account_status="active"
            )
            admin.save()
            print(f"✅ Created admin user {ADMIN_EMAIL}")
        
        print("\n" + "="*60)
        print("🔐 ADMIN CREDENTIALS SET UP")
        print("="*60)
        print(f"Email:    {ADMIN_EMAIL}")
        print(f"Password: {ADMIN_PASSWORD}")
        print(f"Status:   ✅ Active & Verified")
        print(f"Role:     Admin (is_staff=True, is_superuser=True)")
        print("="*60)
        print("\nYou can now login with these credentials at:")
        print("POST http://localhost:8000/api/accounts/token/")
        print("\nAccess admin endpoints:")
        print("GET  http://localhost:8000/api/admin/stats/")
        print("GET  http://localhost:8000/api/admin/skill-tests/")
        print("="*60)
        
    except Exception as e:
        print(f"❌ Error creating admin user: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    setup_admin()
