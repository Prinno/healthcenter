from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.db import models


class User(AbstractUser):
    ROLE_CHOICES = [
        ('patient', 'Patient'),
        ('doctor', 'Doctor'),
    ]
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='doctor')
    phone_number = models.CharField(max_length=15, unique=True)
    email = models.EmailField(unique=True) # Make email unique

    USERNAME_FIELD = 'email'  # Set email as the unique identifier for login
    REQUIRED_FIELDS = ['username','phone_number']  # Add other required fields


    def __str__(self):
        return self.email


class Medicine(models.Model):
    name = models.CharField(max_length=255)
    quantity = models.IntegerField()
    OriPrice = models.IntegerField()
    discprice = models.IntegerField()
    dosage = models.CharField(max_length=255)
    description = models.CharField(max_length=255)
    image = models.ImageField(upload_to='medicine_images/', null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        limit_choices_to={'role': 'doctor'},  # Restrict to supply users only
        related_name='medicine'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.quantity}, {self.discprice})"



      # 'name': medicianitemName,
      # 'quantity': quantityitem,
      # 'OriPrice':originalpriceitem,
      # 'discprice':discountpriceitem,
      # 'dosage':dosageitem,
      # 'description':descriptionitem