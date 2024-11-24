# users/utils.py
from django.contrib.auth.tokens import PasswordResetTokenGenerator



from rest_framework.permissions import BasePermission

class IsDoctorUser(BasePermission):
    def has_permission(self, request, view):
        return getattr(request.user, 'role', None) == 'doctor'

class EmailVerificationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return f"{user.pk}{timestamp}{user.is_active}"

# Create an instance of EmailVerificationTokenGenerator
email_verification_token = EmailVerificationTokenGenerator()



