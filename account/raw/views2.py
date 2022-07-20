from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import UsersTable
from django.contrib.auth.hashers import make_password, check_password
from django.conf import settings
    #for password hashing
import random
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
#for Regex (regular expression)
import re

# import requests
import requests
import json
import urllib

# Create your views here.

##########################################################
# This will run just on page load.

"""
# Password Hashing (working)
from django.contrib.auth.hashers import make_password, check_password

password = "Yubraj@2020"
hashed_password = make_password(password)
print(hashed_password)
fake_hashed_password = "pbkdf2_sha256$320000$6r53QxNWCD0sI03Mpzp3GS$nxl1s5NOT9CtLnVKWY208jbIO1HxUlcr1rSkmFxo="
# check_result = check_password(password,"pbkdf2_sha256$320000$6r53QxNWCD0sI03Mpzp3GS$nxl1s5NOT9CtLnVKWY208jbIO1HxUlcr1rSkmFxlapo=")
check_result = check_password(password, hashed_password)
# check_result = check_password(password, fake_hashed_password)
print(check_result)

"""
# print(get_current_site(request))
# print(get_current_site(request).domain)

# Getting random Number String
# print(random.random())
# randNum = random.random()
# randNumString = str(randNum)
# randWholeNumString = randNumString.split('.')[1]
# print(randNum,randNumString,randWholeNumString)

##########################################################

def get_random_token():
    randNum = random.random()
    randNumString = str(randNum)
    randWholeNumString = randNumString.split('.')[1]
    # print(randNum,randNumString,randWholeNumString)
    return randWholeNumString

# def send_welcome_email(request, userObj):
def send_welcome_email(request, userObj):
    try:
        # Welcome Email
        subject = "Welcome to authentication system!!"
        # current_site = get_current_site(request)
        # domain = current_site.domain
        message ="""
        Welcome !!!
        """
        from_email = settings.EMAIL_HOST_USER
        # to_list = ["imyubraz@gmail.com"]
        # to_list = ["yubrajpoudel@ismt.edu.np",]
        to_list = [userObj.email,]
        send_mail(subject, message, from_email, to_list, fail_silently=True)
        return True
    except:
        pass

def send_confirmation_email(request, userObj):
    try:
        # Welcome Email
        subject = "Welcome to authentication system!!"
        current_site = get_current_site(request)
        domain_name = current_site.domain
        link = f'http://{domain_name}/verify/{userObj.token}'
        message = f'Hello, please click  link to confirm your registration : {link} '        
        
        from_email = settings.EMAIL_HOST_USER
        # to_list = ["imyubraz@gmail.com"]
        # to_list = ["yubrajpoudel@ismt.edu.np",]
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
        # to_list = ["imyubraz@gmail.com"]
        # to_list = ["yubrajpoudel@ismt.edu.np",]
        to_list = [userObj.email,]
        send_mail(subject, message, from_email, to_list, fail_silently=True)
        return True
    except:
        pass

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
    except:
        print("Exception!")
        return False

def signup(request):
    # print(get_current_site(request))
    # print(get_current_site(request).domain)
    try:
        # pass
        if request.method == "POST":
            # Ensuring form submission and it's request method to be post
            if "register_button" in request.POST:
                #to check register_button named button (which is supposed to be triggered for signup form) exists in post request created
                # print("post request detected") #ok
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

                nameRegex = "[a-zA-Z]{2,20}"
                # nameRegex = "^[a-zA-Z]{2,20}$"
                unameRegex = "[a-z0-9_]{3,15}"
                # unameRegex = "\w{3,15}"
                # unameRegex = "^\w{3,15}$"
                emailRegex = "^\w+\.*\w@[a-z]{3,20}\.[a-z]{2,4}\.?[a-z]?[a-z]?"
                # emailRegex = "^\w+\.*\w@[a-z]{3,20}\.[a-z]{2,4}"
                pswdCriterian = {
                    "length_criteria":".{8,}",
                    "lowercase_criteria":"[a-z]+",
                    "uppercase_criteria":"[A-Z]+",
                    "number_criteria":"[0-9]+",
                    "symbol_criteria":"[^A-Za-z0-9]+",
                }
                # isFormValid = True

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
                    # UserObj is an instance of UsersTable model (since it is class) is created where we pass and assign form field value to corresponding field in database.
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
                    # context["isregistered"] = True
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
        # pass
        if request.method == "POST":
            if "login_button" in request.POST:
                uname = request.POST['uname']
                # uname = request.POST.get('uname)
                # email = request.POST['email']
                pswd = request.POST['pswd']
                # print(uname, pswd)
                # print(request.POST)
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
                # pswdRegex = ".{8,50}"

                # if not regexValid(unameRegex, uname):
                #     print("Invalid Username!")
                #     context['formErr']['unameErr'] = "Please enter valid username!"
                #     formErrorFlag = True
                # else:
                #     if not UsersTable.objects.filter(username = uname):
                #         print("Username doesn't exist!")
                #         context['formErr']['unameErr'] = "Username doesn't exist!"
                #         formErrorFlag = True
                #     else:
                #         user = UsersTable.objects.filter(username = uname)[0]
                #         if not check_password(pswd, user.passeord):
                #             print("Incorrect password!")
                #             context['formErr']['pswdErr'] = "Incorrect password!"
                #             formErrorFlag = True

                    
                # user = UsersTable.objects.filter(username = uname)
                    # Gets a user by username
                # user = UsersTable.objects.get(username = uname)
                    # Gets a user by username                
                # user = UsersTable.objects.filter(username = uname)[0]
                    # Get first user if multiple rows or user objects have same username. If [0] was not there it will give queryset of all rows that matches username
                # or
                if not captchaValidation(request):
                    print("invalid captcha")
                    context['error']['captchaErr']= "Invalid Captcha"
                    # form_error["captcha_error"] = "Invalid Captcha"
                    # formErrorFlag = True

                    # if not formErrorFlag:
                    # user = UsersTable.objects.filter(email = uname)
                    # user = UsersTable.objects.filter(username = uname)
                else:
                    user_set_1 = UsersTable.objects.filter(username = uname)
                    print(user_set_1)
                        #getting user by username
                    user_set_2 = UsersTable.objects.filter(email = uname)
                    print(user_set_2)
                        #getting user by email

                    if user_set_1:
                        # print("1")
                        user_set = user_set_1
                    else:
                        # print("2")
                        user_set = user_set_2
                    # This gives dictionary / queryset
                    # print(user_set)

                    # if user:
                    if user_set:
                        # print("ok")
                        userObj = user_set[0]
                        password = userObj.password
                        isVerified = userObj.is_verified
                        # print(password)
                        passFlag = check_password(pswd, password)
                        # verifyFlag = False
                        # if isVerified:
                            # verifyFlag = True
                        if not isVerified:
                            print("Not verified!")
                            context['error']['verifyErr'] = "User is not verified yet!"
                            # formErrorFlag = True
                        else:
                            if passFlag:
                                print("Success!")
                                request.session['user'] = userObj.id
                                request.session['email'] = userObj.email
                                request.session['username'] = userObj.username
                                # print(request.session['user'])
                                # return redirect('profile')
                                return redirect('index')

                            # if request.session['user']:
                            #     return redirect('profile')
                            # else:
                            #     return redirect('home')
                                # return redirect('profile')
                                # returns true if user.password is hashed password of pswd
                            # if flag:
                            #     # print("Correct password!")
                            #     # return redirect('index')
                            #     # return redirect('profile')
                            #     context = {
                            #         "userData" : {
                            #             "fname" : userObj.first_name,
                            #             "lname" : userObj.last_name,
                            #             "username" : userObj.username,
                            #             "email" : userObj.email
                            #         }
                            #     }
                            #     templatePath = "account/profile.html"
                            #     response = render(request, templatePath, context)
                            #     return response

                            # else:
                            #     print("Can't Login!")
                            #     print("Verify email!")
                            else:
                                context['error']['credErr'] = "Invalid Credentials!"


                    else:
                        print("Username or Email do not exist!")
                        # templatePath = "account/login.html"
                        context['error']['credErr'] = "Invalid Credentials!"
                        response = render(request, templatePath, context)
                        return response
                        # return redirect("index")  
                # else:
                #     # print("Username or Email do not exist!")
                #     templatePath = "account/login.html"
                #     response = render(request, templatePath, context)
                #     return response
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
            # Since user is a query set !
        temp.is_verified = True
        temp.save()
        # user.save()
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
    # print(request.session['user'])
    # print(request.session['username'])
    context = {}
    try:
        session = request.session
        if session['username']:
            # context['isAuthenticated'] = True
            # context['username'] = session['username']
            # context['username'] = request.session['username']
            # userObj = UsersTable.objects.get(username = session['username']) # not working ??
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
        # CLear Session
    return redirect('index')

# def handle_post_request(request)

def forget_password(request):
    templatePath = "account/forgetpassword.html"
    context = {}
    try:
        if request.method == "POST":
            # print("ok")
            if "send_button" in request.POST:
                email = request.POST['email']
                # print(email)
                user = UsersTable.objects.filter(email = email)
                # user = UsersTable.objects.get(email = email)
                if user:
                    print("exists")
                    # context["userExistFlag"] = True
                    userObj = user[0]
                    send_password_reset_email(request, userObj)
                    context["userExists"] = True
                    context["messages"] = {
                        "successMsg": "Password reset link sent to your email successfully."
                    }
                    # context["userExists"] = "yes"
                    print(context)
                else:
                    print("dont exists")
                    context["userExists"] = False
                    context["messages"] = {
                        "errorMsg": "Email is not registered yet ! Please enter a registered email."
                    }
                    # context["userExists"] = "no"
                    # context["userExistFlag"] = "False"
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
        # print("exists")
        # userObj = user[0]
        try:
            if request.method == "POST":
                # print("ok")
                if "reset_button" in request.POST:
                    # print("ok")
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
                    # if pswd == userObj.password :
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

    
# def change_password(request):
#     context = {}
#     templatePath = "account/changepassword.html"
#     response = render(request, templatePath, context)
#     return response
    

def change_password(request):
    try:
        session = request.session
        if session['username']:
            user_set = UsersTable.objects.filter(username = session['username'])
            userObj = user_set[0]
            templatePath = "account/changepassword.html"
            try:
                if request.method == "POST":
                    # print("ok")
                    if "change_button" in request.POST:
                        print("okkk")
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
                            print("match")
                            #validation
                            pswdCriterian = {
                                "length_criteria":".{8,}",
                                "lowercase_criteria":"[a-z]+",
                                "uppercase_criteria":"[A-Z]+",
                                "number_criteria":"[0-9]+",
                                "symbol_criteria":"[^A-Za-z0-9]+",
                            }
                            #Password criteria check
                            # if check_password(npswd, userObj.password):
                            #     context['formErr']['pswdErr'] = "You cannot set old password as new password...."
                            #     formErrorFlag = True
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
                            # print("else")
                            templatePath = "account/changepassword.html"
                            print(context)
                            response = render(request, templatePath, context)
                            return response
                        else:
                            hash_pswd = make_password(npswd)
                            print(userObj.password)
                            userObj.password = hash_pswd
                            userObj.save()
                            # context["successMsg"]="Password Changed Successfully!"
                            context = {
                                "successMsg": "Password Changed Successfully!"
                            }
                            print("Changed")
                            templatePath = "account/changepassword.html"
                            # print(context)
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
