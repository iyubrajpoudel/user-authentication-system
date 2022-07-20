from django.urls import path, include
from home import views
# from home.views import index

urlpatterns = [
    path('', views.index, name="index"),
    # path('', index, name="index"),
]
