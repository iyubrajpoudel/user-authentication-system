from django import forms
from .models import UsersTable

class UserRegistrationForm(forms.form):
    class Meta:
        model = UsersTable
        fields = ('email')
