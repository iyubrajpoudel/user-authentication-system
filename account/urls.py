from django.urls import path, include
from account import views

urlpatterns = [
    path('signup/', views.signup, name="signup"),
    path('login/', views.login, name="login"),
    path('verify/<token>', views.verify, name="verify"),
    path('profile/', views.profile, name="profile"),
    path('profile/changepassword', views.change_password, name="changepassword"),
    path('logout/', views.logout, name="logout"),
    path('forgetpassword/', views.forget_password, name="forgetpassword"),
    path('resetpassword/<token>', views.reset_password, name="resetpassword"),
]
