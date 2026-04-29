#!/usr/bin/env python
"""
Verify Admin User Credentials
"""

import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'FreelancerBackend.settings')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
django.setup()

from accounts.models import CustomUser
from django.contrib.auth.hashers import check_password, make_password

# Admin credentials
ADMIN_EMAIL = "Admin@NX.com"
ADMIN_PASSWORD = "Admin@itadmin"

def verify_admin():
    """Verify admin user exists and credentials work"""
    try:
        # Check if admin exists
        admin = CustomUser.objects(email=ADMIN_EMAIL).first()
        
        if not admin:
            print(f"❌ Admin user '{ADMIN_EMAIL}' NOT FOUND in database!")
            print("Creating admin now...")
            admin = CustomUser(
                email=ADMIN_EMAIL,
                password=make_password(ADMIN_PASSWORD),
                role="client",
                is_staff=True,
                is_superuser=True,
                is_active=True,
                email_verified=True,
                face_verified=True,  # Mark as verified so no face verification required
                account_status="active"
            )
            admin.save()
            print(f"✅ Created admin user {ADMIN_EMAIL}")
        
        print(f"\n✅ Admin user found: {admin.email}")
        print(f"   is_staff: {admin.is_staff}")
        print(f"   is_superuser: {admin.is_superuser}")
        print(f"   is_active: {admin.is_active}")
        print(f"   email_verified: {admin.email_verified}")
        print(f"   face_verified: {admin.face_verified}")
        print(f"   account_status: {admin.account_status}")
        
        # Test password
        print(f"\n🔐 Testing password verification...")
        password_correct = check_password(ADMIN_PASSWORD, admin.password)
        print(f"   Password correct: {password_correct}")
        
        if not password_correct:
            print(f"\n⚠️  Password mismatch! Resetting password...")
            admin.password = make_password(ADMIN_PASSWORD)
            admin.save()
            print(f"✅ Password reset for {ADMIN_EMAIL}")
        
        print("\n" + "="*60)
        print("✅ ADMIN VERIFICATION COMPLETE")
        print("="*60)
        print(f"Email:    {ADMIN_EMAIL}")
        print(f"Password: {ADMIN_PASSWORD}")
        print(f"Status:   Ready to login")
        print("="*60)
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    verify_admin()
