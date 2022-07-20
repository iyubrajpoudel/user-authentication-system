from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import UsersTable
    #for password hashing
from django.contrib.auth.hashers import make_password, check_password
#for Regex (regular expression)
import re

# import requests (for google recaptcha)
import requests
import json
import urllib

    #for email sending
from django.conf import settings
import random
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail

def get_random_token():
    randNum = random.random()
    randNumString = str(randNum)
    randWholeNumString = randNumString.split('.')[1]
    return randWholeNumString

     #for email sending
def send_welcome_email(request, userObj):
    try:
        subject = "Welcome to authentication system!!"
        message ="""
        Welcome !!!
        """
        from_email = settings.EMAIL_HOST_USER
        to_list = [userObj.email,]
        send_mail(subject, message, from_email, to_list, fail_silently=True)
        return True
    except:
        pass

def send_confirmation_email(request, userObj):
    try:
        subject = "Welcome to authentication system!!"
        current_site = get_current_site(request)
        domain_name = current_site.domain
        link = f'http://{domain_name}/verify/{userObj.token}'
        message = f'Hello, please click  link to confirm your registration : {link} '        
        
        from_email = settings.EMAIL_HOST_USER
        to_list = [userObj.email,]
        send_mail(subject, message, from_email, to_list, fail_silently=True)
        return True
    except:
        pass

def send_password_reset_email(request, userObj):
    try:
        # Welcome Email
        subject = "Password Reset Link"
        current_site = get_current_site(request)
        domain_name = current_site.domain
        link = f'http://{domain_name}/resetpassword/{userObj.token}'
        message = f'Click link to reset password : {link} '        
        from_email = settings.EMAIL_HOST_USER
        to_list = [userObj.email,]
        send_mail(subject, message, from_email, to_list, fail_silently=True)
        return True
    except:
        pass

    # for regex validation
def regexValid(regex, data):
    try:
        if (re.search(regex, data)):
            return True
    except Exception as ex:
        print(ex)

def captchaValidation(request):
    try:
        recaptcha_response = request.POST.get('g-recaptcha-response')
        data = {
            'secret': settings.GOOGLE_RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response
        }
        r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
        result = r.json()
        if result['success']:
            return True
    except Exception as ex:
        print("Exception :", ex)
        return False

def signup(request):
    try:
        if request.method == "POST":
            if "register_button" in request.POST:
                fname = request.POST['fname']
                lname = request.POST['lname']
                uname = request.POST['uname']
                email = request.POST['email']
                pswd = request.POST['pswd']
                cpswd = request.POST['cpswd']
                print(fname)
                context = {
                    "formData" : {},
                    "formErr" : {}
                }

                # for sending form field inputs
                context['formData']['fname'] = fname
                context['formData']['lname'] = lname
                context['formData']['uname'] = uname
                context['formData']['email'] = email
                context['formData']['pswd'] = pswd
                context['formData']['cpswd'] = cpswd

                formErrorFlag = False

                # for regex validation

                nameRegex = "[a-zA-Z]{2,20}"
                unameRegex = "[a-z0-9_]{3,15}"
                emailRegex = "^\w+\.*\w@[a-z]{3,20}\.[a-z]{2,4}\.?[a-z]?[a-z]?"
                pswdCriterian = {
                    "length_criteria":".{8,}",
                    "lowercase_criteria":"[a-z]+",
                    "uppercase_criteria":"[A-Z]+",
                    "number_criteria":"[0-9]+",
                    "symbol_criteria":"[^A-Za-z0-9]+",
                }
                if not regexValid(nameRegex, fname):
                    print("Invalid First Name!")
                    context['formErr']['fnameErr'] = "Please enter valid firstname!"
                    formErrorFlag = True

                if not regexValid(nameRegex, lname):
                    print("Invalid Last Name!")
                    context['formErr']['lnameErr'] = "Please enter valid lastname!"
                    formErrorFlag = True
                    
                if not regexValid(unameRegex, uname):
                    print("Invalid Userame!")
                    context['formErr']['unameErr'] = "Please enter valid username!"
                    formErrorFlag = True
                else:
                    if UsersTable.objects.filter(username = uname):
                        print("Username taken!")
                        context['formErr']['unameErr'] = "Username taken!"
                        formErrorFlag = True

                if not regexValid(emailRegex, email):
                    print("Invalid Email!")
                    context['formErr']['emailErr'] = "Please enter valid email!"
                    formErrorFlag = True
                else:
                    if UsersTable.objects.filter(email = email):
                        print("Email is already registered!")
                        context['formErr']['emailErr'] = "Email already registered!"
                        formErrorFlag = True
                
                #Password criteria check
                if not(re.search(pswdCriterian["length_criteria"], pswd) and re.search(pswdCriterian["lowercase_criteria"], pswd) and re.search(pswdCriterian["uppercase_criteria"], pswd) and re.search(pswdCriterian["number_criteria"], pswd) and re.search(pswdCriterian["symbol_criteria"], pswd)):
                    print("pswd cr result")
                    context['formErr']['pswdErr'] = "Please meet all password criterian...."
                    formErrorFlag = True

                if cpswd != pswd:
                    print("Password & Confirm Password do not match!")
                    context['formErr']['cpswdErr'] = "Password & Confirm Password do not match!"
                    formErrorFlag = True
                
                if not captchaValidation(request):
                    print("invalid captcha")
                    context['formErr']['captchaErr'] = "Invalid Captcha"
                    formErrorFlag = True

                if formErrorFlag:
                    context['hasError'] = True
                    templatePath = "account/signup.html"
                    response = render(request, templatePath, context)
                    return response
                else:
                    hash_pswd = make_password(pswd)
                    userObj = UsersTable(first_name=fname, last_name=lname, username=uname, email=email, password=hash_pswd)
                    token = get_random_token()
                    userObj.token = token
                    userObj.save()
                    if send_welcome_email(request, userObj):
                        print("Sent!!")
                    else:
                        print("Not Sent!!")
                    if send_confirmation_email(request, userObj):
                        print("C Sent!!")
                    else:
                        print("C Not Sent!!")
                    
                    templatePath = "account/signup.html"
                    response = render(request, templatePath, {"isRegistered":True})
                    return response     
    except Exception as e:
        print(e)
        pass
    templatePath = "account/signup.html"
    context = {}
    response = render(request, templatePath, context)
    return response

def login(request):
    try:
        if request.method == "POST":
            if "login_button" in request.POST:
                uname = request.POST['uname']
                pswd = request.POST['pswd']
                templatePath = "account/login.html"
                context = {
                    "data" : {},
                    "error" : {}
                }
                
                # for sending form field inputs
                context['data']['uname'] = uname
                context['data']['pswd'] = pswd

                formErrorFlag = False
                unameRegex = "\w{3,15}"
                if not captchaValidation(request):
                    print("invalid captcha")
                    context['error']['captchaErr']= "Invalid Captcha"
                else:
                    user_set_1 = UsersTable.objects.filter(username = uname)
                    print(user_set_1)
                    user_set_2 = UsersTable.objects.filter(email = uname)
                    print(user_set_2)

                    if user_set_1:
                        user_set = user_set_1
                    else:
                        user_set = user_set_2

                    # if user:
                    if user_set:
                        userObj = user_set[0]
                        password = userObj.password
                        isVerified = userObj.is_verified
                        passFlag = check_password(pswd, password)
                        if not isVerified:
                            context['error']['verifyErr'] = "User is not verified yet!"
                        else:
                            if passFlag:
                                request.session['user'] = userObj.id
                                request.session['email'] = userObj.email
                                request.session['username'] = userObj.username
                                return redirect('index')
                            else:
                                context['error']['credErr'] = "Invalid Credentials!"
                    else:
                        print("Username or Email do not exist!")
                        context['error']['credErr'] = "Invalid Credentials!"
                        response = render(request, templatePath, context)
                        return response
            response = render(request, templatePath, context)
            return response
    except Exception as e:
        print(e)
        pass   
    templatePath = "account/login.html"
    context = {}
    response = render(request, templatePath, context)
    return response

def verify(request, token):
    user = UsersTable.objects.filter(token=token)
    if user:
        print("Verified!")
        temp = user[0]
        temp.is_verified = True
        temp.save()
        templatePath = "account/verify.html"
        context = {
            "verifyFlag": True,
            "msg": "Verification Success!"
        }
        response = render(request, templatePath, context)
        return response
    templatePath = "account/verify.html"
    context = {
        "verifyFlag": False,
        "msg": "Verification failed!"
    }
    response = render(request, templatePath, context)
    return response

def profile(request):
    context = {}
    try:
        session = request.session
        if session['username']:
            userObj = UsersTable.objects.filter(username = session['username'])
            print(userObj)
            context = {
                "isAuthenticated": True,
                "userData": {
                    "fname": userObj[0].first_name,
                    "lname": userObj[0].last_name,
                    "username": userObj[0].username,
                    "email": userObj[0].email,
                }
            }
            templatePath = "account/profile.html"
    except Exception as e:
        print(e)
        # templatePath = "404.html"
        templatePath = "login_required.html"
    response = render(request, templatePath, context)
    return response

def logout(request):
    request.session.clear()
    return redirect('index')

def forget_password(request):
    templatePath = "account/forgetpassword.html"
    context = {}
    try:
        if request.method == "POST":
            if "send_button" in request.POST:
                email = request.POST['email']
                user = UsersTable.objects.filter(email = email)
                if user:
                    print("exists")
                    userObj = user[0]
                    send_password_reset_email(request, userObj)
                    context["userExists"] = True
                    context["messages"] = {
                        "successMsg": "Password reset link sent to your email successfully."
                    }
                    print(context)
                else:
                    print("dont exists")
                    context["userExists"] = False
                    context["messages"] = {
                        "errorMsg": "Email is not registered yet ! Please enter a registered email."
                    }
                response = render(request, templatePath, context)
                return response
    except Exception as e:
        print(e)
    response = render(request, templatePath, context)
    return response

def reset_password(request, token):
    user_set = UsersTable.objects.filter(token = token)
    if user_set:
        userObj = user_set[0]
        try:
            if request.method == "POST":
                if "reset_button" in request.POST:
                    pswd = request.POST['pswd']
                    cpswd = request.POST['cpswd']
                    context = {
                        "formData": {
                            "pswd": pswd,
                            "cpswd": cpswd
                        },
                        "formErr": {},
                    }
                    #validation
                    pswdCriterian = {
                        "length_criteria":".{8,}",
                        "lowercase_criteria":"[a-z]+",
                        "uppercase_criteria":"[A-Z]+",
                        "number_criteria":"[0-9]+",
                        "symbol_criteria":"[^A-Za-z0-9]+",
                    }

                    formErrorFlag = False

                    #Password criteria check
                    if check_password(pswd, userObj.password):
                        context['formErr']['pswdErr'] = "You cannot set old password as new password...."
                        formErrorFlag = True
                    else:
                        if not(re.search(pswdCriterian["length_criteria"], pswd) and re.search(pswdCriterian["lowercase_criteria"], pswd) and re.search(pswdCriterian["uppercase_criteria"], pswd) and re.search(pswdCriterian["number_criteria"], pswd) and re.search(pswdCriterian["symbol_criteria"], pswd)):
                            print("pswd cr result")
                            context['formErr']['pswdErr'] = "Please meet all password criterian...."
                            # formErrorFlag = True
                        if cpswd != pswd:
                            print("Password & Confirm Password do not match!")
                            context['formErr']['cpswdErr'] = "Password & Confirm Password do not match!"
                            formErrorFlag = True
                        
                    if formErrorFlag:
                        # print("else")
                        templatePath = "account/resetpassword.html"
                        response = render(request, templatePath, context)
                        return response
                    else:
                        # print("hjkbhjn")
                        hash_pswd = make_password(pswd)
                        # print(userObj.password)
                        userObj.password = hash_pswd
                        userObj.save()
                        print("Changed")
                        context = {
                            "successMsg": "Password has been changed successfully!"
                        }
                        templatePath = "account/resetpassword.html"
                        response = render(request, templatePath, context)
                        return response
            else:
                templatePath = "account/404.html"
                response = render(request, templatePath, context)
                return response
        except Exception as e:
            print(e)
        # print(userObj.password)
        templatePath = "account/resetpassword.html"
        context = {}
        response = render(request, templatePath, context)
        return response
    else:
        templatePath = "invalid_token.html"
        response = render(request, templatePath)
        return response

def change_password(request):
    try:
        session = request.session
        if session['username']:
            user_set = UsersTable.objects.filter(username = session['username'])
            userObj = user_set[0]
            templatePath = "account/changepassword.html"
            try:
                if request.method == "POST":
                    if "change_button" in request.POST:
                        pswd = request.POST['pswd']
                        npswd = request.POST['npswd']
                        cnpswd = request.POST['cnpswd']
                        context = {
                            "formData": {
                                "pswd": pswd,
                                "npswd": npswd,
                                "cnpswd": cnpswd
                            },
                            "formErr": {}
                        }
                        print(pswd,npswd,cnpswd,userObj.password)
                        formErrorFlag = False
                        if check_password(pswd, userObj.password):
                            #validation
                            pswdCriterian = {
                                "length_criteria":".{8,}",
                                "lowercase_criteria":"[a-z]+",
                                "uppercase_criteria":"[A-Z]+",
                                "number_criteria":"[0-9]+",
                                "symbol_criteria":"[^A-Za-z0-9]+",
                            }
                            if npswd == pswd:
                                context['formErr']['npswdErr'] = "You cannot set old password as new password...."
                                formErrorFlag = True
                            else:
                                if not(re.search(pswdCriterian["length_criteria"], npswd) and re.search(pswdCriterian["lowercase_criteria"], npswd) and re.search(pswdCriterian["uppercase_criteria"], npswd) and re.search(pswdCriterian["number_criteria"], npswd) and re.search(pswdCriterian["symbol_criteria"], npswd)):
                                    context['formErr']['npswdErr'] = "Please meet all password criterian...."
                                    formErrorFlag = True
                                if cnpswd != npswd:
                                    print("Password & Confirm Password do not match!")
                                    context['formErr']['cnpswdErr'] = "New Password & Confirm New Password do not match!"
                                    formErrorFlag = True
                        else:
                            print("not match")
                            formErrorFlag = True
                            context['formErr']['pswdErr'] = "Incorrect old password!"
                            
                        if formErrorFlag:
                            templatePath = "account/changepassword.html"
                            response = render(request, templatePath, context)
                            return response
                        else:
                            hash_pswd = make_password(npswd)
                            print(userObj.password)
                            userObj.password = hash_pswd
                            userObj.save()
                            context = {
                                "successMsg": "Password Changed Successfully!"
                            }
                            print("Changed")
                            templatePath = "account/changepassword.html"
                            response = render(request, templatePath, context)
                            return response
            except Exception as e:
                print(e)
            context={}
            response = render(request, templatePath, context)
            return response
        else:
            templatePath = "login_required.html"
            response = render(request, templatePath)
            return response
    except Exception as e:
        print(e)
        templatePath = "login_required.html"
    templatePath = "login_required.html"
    response = render(request, templatePath)
    return response
