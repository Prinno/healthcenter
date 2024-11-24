from rest_framework import serializers
from .models import User,Medicine
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import PasswordResetTokenGenerator,default_token_generator
from django.core.mail import send_mail
from django.conf import settings
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.urls import reverse
from .utils import email_verification_token
from django.contrib.auth import get_user_model
from django.conf import settings
User = get_user_model()




class MedicineSerializer(serializers.ModelSerializer):
    class Meta:
        model = Medicine
        fields = ['name', 'quantity', 'OriPrice','discprice','dosage','description','image']




class MedicineListSerializer(serializers.ModelSerializer):
    imageUrl = serializers.SerializerMethodField()

    def get_imageUrl(self, obj):
        request = self.context.get('request')
        if obj.image and request:  # Assuming `image` is the field for the image path
            return request.build_absolute_uri(obj.image.url)
        return None

    class Meta:
        model = Medicine
        fields = ['id', 'name', 'quantity', 'OriPrice', 'discprice', 'dosage', 'description', 'imageUrl', 'created_at']


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")
        return value

    def save(self):
        user = User.objects.get(email=self.validated_data['email'])
        token = default_token_generator.make_token(user)
        
        # Base64 encode user pk
        uidb64 = urlsafe_base64_encode(str(user.pk).encode())

        reset_url = f"http://localhost:8000/reset_password/{uidb64}/{token}/"

        # Send password reset email
        send_mail(
            subject="Password Reset Request",
            message=f"Click the link to reset your password: {reset_url}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
        )


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'phone_number', 'password', 'password2', 'role')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            email=validated_data['email'],
            username=validated_data['username'],
            phone_number=validated_data['phone_number'],
            role='patient'
        )
        user.set_password(validated_data['password'])
        user.save()
        return user



class EmailVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email']

    def send_verification_email(self, user):
        token = email_verification_token.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        verification_url = f"http://localhost:8000/users/verify-email/{uid}/{token}/"
        
        send_mail(
            subject="Verify Your Email",
            message=f"Please verify your email by clicking the following link: {verification_url}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
        )



