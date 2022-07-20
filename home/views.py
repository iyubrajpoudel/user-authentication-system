from django.shortcuts import render
from django.http import HttpResponse

# Create your views here.

def index(request):
    # response = HttpResponse("Index Page")
    templatePath = "home/index.html"
    # templatePath = "404.html"
    context = {}
    response = render(request, templatePath, context)
    return response