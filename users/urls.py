from django.urls import path
from .views import MedicineDetailView, AddMedicineView,MedicineListView,MedicineListAllView, RegisterView,SendVerificationEmailView,ResetPasswordView, VerifyEmailView,PasswordResetView,LoginView,PasswordResetConfirmView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('send-verification-email/', SendVerificationEmailView.as_view(), name='send_verification_email'),
    path('verify-email/<uidb64>/<token>/', VerifyEmailView.as_view(), name='verify_email'),
    path('password_reset/', PasswordResetView.as_view(), name='password_reset'),
    path('reset_password/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset_password/<uidb64>/<token>/', ResetPasswordView.as_view(), name='reset_password'),
    path('login/', LoginView.as_view(), name='login'),
    path('api/medicine/', AddMedicineView.as_view(), name='add_mediceni'),
    path('api/medicines/', MedicineListView.as_view(), name='medicine_list'),
    path('medicines/<int:pk>/', MedicineDetailView.as_view(), name='medicine-detail'),  
    path('api/allpatientmedicineslis/', MedicineListAllView.as_view(), name='medicine_list_all'),
]