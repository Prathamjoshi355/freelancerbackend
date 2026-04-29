#!/usr/bin/env python
"""
Enable Face Verification for Admin
"""

import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'FreelancerBackend.settings')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
django.setup()

from accounts.models import CustomUser

admin = CustomUser.objects(email='Admin@NX.com').first()
if admin:
    admin.face_verified = True
    admin.save()
    print('✅ Admin face verified! You can now login.')
else:
    print('❌ Admin user not found')
