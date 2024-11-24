# users/views.py
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User,Medicine
from .utils import email_verification_token
from .serializers import MedicineSerializer,MedicineListSerializer,RegisterSerializer, EmailVerificationSerializer, PasswordResetSerializer
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.shortcuts import render
from django.contrib.auth.forms import SetPasswordForm
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import RetrieveUpdateDestroyAPIView
from .utils import IsDoctorUser

User = get_user_model()




class MedicineDetailView(RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated, IsDoctorUser]
    serializer_class = MedicineSerializer

    def get_queryset(self):
        # Filter medicines belonging to the authenticated user
        return Medicine.objects.filter(created_by=self.request.user)

    def update(self, request, *args, **kwargs):
        # Ensure only 'doctor' role can update
        if getattr(request.user, 'role', None) != 'doctor':
            return Response(
                {"error": "Permission denied. Only doctor users can update medicine."},
                status=status.HTTP_403_FORBIDDEN
            )
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        # Ensure only 'doctor' role can delete
        if getattr(request.user, 'role', None) != 'doctor':
            return Response(
                {"error": "Permission denied. Only doctor users can delete medicine."},
                status=status.HTTP_403_FORBIDDEN
            )
        return super().destroy(request, *args, **kwargs)


class MedicineListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        medicines = Medicine.objects.filter(created_by=request.user)  # Filter medicines as per your logic
        serializer = MedicineListSerializer(medicines, many=True, context={'request': request})
        return Response(serializer.data)



class MedicineListAllView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        medicines = Medicine.objects.all()  # Filter medicines as per your logic
        serializer = MedicineListSerializer(medicines, many=True, context={'request': request})
        return Response(serializer.data)



class AddMedicineView(APIView):
    permission_classes = [IsAuthenticated]  

    def post(self, request):
        # Ensure the user has a 'doctor' role
        # Check if the user has a 'doctor' role (adjust the role check if needed)
        if not request.user.is_authenticated or getattr(request.user, 'role', None) != 'doctor':
            return Response(
                {"error": "Permission denied. Only doctor users can add medicine informations."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Validate and save the medicine data using the serializer
        serializer = MedicineSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(created_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            print(serializer.errors)  # Add this line to check for specific validation errors
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({'error': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)

        # Authenticate user using the custom email backend
        user = authenticate(request, email=email, password=password)

        if user is not None:
            if user.is_active:
                # Assign role based on user attributes or role field
                role = 'patient' if user.role == 'patient' else 'doctor'
                
                # Generate JWT token
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)

                # Return both role and access_token
                return Response({
                    'message': 'Login successful',
                    'role': role,
                    'access_token': access_token
                }, status=status.HTTP_200_OK)
            
            return Response({'error': 'Account is inactive.'}, status=status.HTTP_403_FORBIDDEN)
        
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)



class ResetPasswordView(APIView):

    def get(self, request, uidb64, token):
        try:
            # Decode the uidb64 to get the user ID
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({'error': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the token is valid
        if not default_token_generator.check_token(user, token):
            return Response({'error': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)

        # Render a page to reset the password
        return render(request, 'reset_password_form.html', {'uidb64': uidb64, 'token': token})

    def post(self, request, uidb64, token):
        try:
            # Decode the uidb64 to get the user ID
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({'error': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the token is valid
        if not default_token_generator.check_token(user, token):
            return Response({'error': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)

        # Set the new password from the request
        new_password = request.data.get('password')
        if new_password:
            user.set_password(new_password)
            user.save()
            return Response({'message': 'Password successfully reset.'}, status=status.HTTP_200_OK)
        return Response({'error': 'Password is required.'}, status=status.HTTP_400_BAD_REQUEST)



class PasswordResetView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Password reset link sent"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmView(APIView):
    def post(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()  # Decode the user ID
            user = User.objects.get(pk=uid)  # Retrieve the user using the decoded ID
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            # Process password reset
            new_password = request.data.get('new_password')
            user.set_password(new_password)
            user.save()
            return Response({"message": "Password reset successful"}, status=status.HTTP_200_OK)
        return Response({"error": "Invalid or expired link"}, status=status.HTTP_400_BAD_REQUEST)




class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer

    def perform_create(self, serializer):
        user = serializer.save()
        user.is_active = False  # Make user inactive until email verification
        user.save()
        EmailVerificationSerializer().send_verification_email(user)




class SendVerificationEmailView(APIView):
    def post(self, request):
        user = request.user  # Or get the user from the registration process
        serializer = EmailVerificationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.send_verification_email(user)
            return Response({"message": "Verification email sent."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



# users/views.py
class VerifyEmailView(APIView):
    permission_classes = [AllowAny]  # Allow unauthenticated access

    def get(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = get_object_or_404(User, pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"error": "Invalid user ID."}, status=status.HTTP_400_BAD_REQUEST)

        if user is not None and email_verification_token.check_token(user, token):
            user.is_active = True
            user.save()
            return Response({"message": "Email verified successfully!"}, status=status.HTTP_200_OK)
        
        return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)



