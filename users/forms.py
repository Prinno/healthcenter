# users/forms.py

from django import forms
from django.contrib.auth.hashers import make_password

class SupplyUserCreationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, label="Password")  # Add password field

    class Meta:
        model = User
        fields = ['username', 'email', 'phone_number', 'password']  # Include password in fields


    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("A user with this email already exists.")
        return email

    def save(self, commit=True):
        user = super().save(commit=False)
        user.is_supply = True  # Set your custom field if applicable
        user.password = make_password(self.cleaned_data['password'])  # Hash the password
        if commit:
            user.save()
        return user




# from django import forms
# from django.contrib.auth import get_user_model

# User = get_user_model()

# class SupplyUserCreationForm(forms.ModelForm):
#     class Meta:
#         model = User
#         fields = ['username', 'email', 'phone_number']

#     def save(self, commit=True):
#         user = super().save(commit=False)
#         user.is_supply = True  # Assuming `is_supply` is a boolean field indicating a supply user
#         user.set_password(User.objects.make_random_password())  # Set a random password
#         if commit:
#             user.save()
#         return user
