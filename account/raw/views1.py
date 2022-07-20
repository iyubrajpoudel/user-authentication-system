from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import UsersTable
from django.contrib.auth.hashers import make_password, check_password
    #for password hashing
import random
from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
#for Regex (regular expression)
import re

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
print(random.random())
randNum = random.random()
randNumString = str(randNum)
randWholeNumString = randNumString.split('.')[1]
print(randNum,randNumString,randWholeNumString)

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

def regexValid(regex, data):
    try:
        if (re.search(regex, fname)):
            return True;
    except Exception as ex:
        print(ex)

def checkPassword(password):
    pswdCriterian = {
    "length_criteria":".{8,}",
    "lowercase_criteria":"[a-z]+",
    "uppercase_criteria":"[A-Z]+",
    "number_criteria":"[0-9]+",
    "symbol_criteria":"[^A-Za-z0-9]+", # her ^ => not
    }
    meetCriterian = True
    pswdErrors = {}
    if not regexValid(pswdCriterian["length_criteria"], password):
        pswdErrors["lengthError"] = "Password must have more then 8 characters!"
        meetCriterian = False
    if not regexValid(pswdCriterian["lowercase_criteria"], password):
        pswdErrors["lcaseError"] = "Password must have a lowercase character!"
        meetCriterian = False
    if not regexValid(pswdCriterian["uppercase_criteria"], password):
        pswdErrors["ucaseError"] = "Password must have a uppercase character!"
        meetCriterian = False
    if not regexValid(pswdCriterian["number_criteria"], password):
        pswdErrors["ucaseError"] = "Password must have a number !"
        meetCriterian = False
    if not regexValid(pswdCriterian["symbol_criteria"], password):
        pswdErrors["ucaseError"] = "Password must have a symbol !"
        meetCriterian = False
    
    result = {
        "flag" : meetCriterian,
        "errors" : pswdErrors
    }

    return result

def validateSignUpForm(request):
    try: 
        fname = request.POST['fname']
        lname = request.POST['lname']
        uname = request.POST['uname']
        email = request.POST['email']
        pswd = request.POST['pswd']
        cpswd = request.POST['cpswd']

            # Defining Regex
        nameRegex = "^[a-zA-Z]{2,20}$"
        unameRegex = "^\w{3,15}$"
        emailRegex = "^\w+\.*\w@[a-z]{3,20}\.[a-z]{2,4}"

        isValid = True;     
        formErrors = {}      
        if not regexValid(nameRegex, fname):
            isValid = False
            formerrors['fnameError'] = "Please enter valid first name!"
        
        if not regexValid(nameRegex, lname):
            isValid = False
            formerrors['lnameError'] = "Please enter valid last name!"
        
        if not regexValid(unameRegex, uname):
            isValid = False
            formerrors['unameError'] = "Please enter valid username!"
        
        if not regexValid(emailRegex, email):
            isValid = False
            formerrors['emailError'] = "Please enter valid email!"

        checkPassword = checkPassword(pswd)

        if not checkPassword['flag']:
            isValid = False
            formerrors['pswdError'] = checkPassword['errors']

        result = {
            "flag": isValid,
            "errors": formErrors
        }

        return result

    except Exception as e:
        print(e)
        pass


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
                    # fname => py variable , ['fname'] wala fname => name of input field (defined in signup.html)
                # fname = request.POST.get('fname)
                lname = request.POST['lname']
                uname = request.POST['uname']
                email = request.POST['email']
                pswd = request.POST['pswd']
                cpswd = request.POST['cpswd']
                # print(fname, lname)
                # print(request.POST)
                    # It will pring entire form data as querydict (dictionary ??) where key value pair of field_name & field_value is shown.

                    # Checking whether username & email already exists
                # print(UsersTable.objects.filter(username = uname))

                    # Form Validation
                
                formData = {
                    "fname": fname,
                    "lname": lname,
                    "uname": uname,
                    "email": email,
                }

                    ## for sending form field inputs
                # context['formData']['fname'] = fname
                # context['formData']['lname'] = lname
                # context['formData']['uname'] = uname
                # context['formData']['email'] = email
                # context['formData']['pswd'] = pswd
                # context['formData']['cpswd'] = cpswd

                isFormValid = True;

                formCheck = validateSignUpForm(request)

                if not formCheck["flag"]:
                    isFormValid = False

                if isFormValid:
                    if UsersTable.objects.filter(username = uname):
                        print("Username taken!")
                    if UsersTable.objects.filter(email = email):
                        print("Email is already registered!")
                        # return False
                    # userObj = UsersTable(first_name=fname, last_name=lname, username=uname, email=email, password=pswd)
                    hash_pswd = make_password(pswd)
                    userObj = UsersTable(first_name=fname, last_name=lname, username=uname, email=email, password=hash_pswd)
                    # UserObj is an instance of UsersTable model (since it is class) is created where we pass and assign form field value to corresponding field in database.
                    token = get_random_token()
                    userObj.token = token
                    userObj.save()
                    # Saving the instance just created which will perform data insertion accordingly.
                    # print("Saved!!")
                    # return redirect("index")
                    if send_welcome_email(request, userObj):
                        print("Sent!!")
                    else:
                        print("Not Sent!!")
                    if send_confirmation_email(request, userObj):
                        print("C Sent!!")
                    else:
                        print("C Not Sent!!")

                    templatePath = "account/signup.html"
                    context = {
                        "isRegistered": True
                    }
                    response = render(request, templatePath, context)
                    return response
                else:
                    templatePath = "account/signup.html"
                    context = {
                        "formErrors": formCheck['errors'],
                        "formData" : formData
                    }
                    response = render(request, templatePath, context)
                
    except Exception as e:
        print(e)
        pass
    templatePath = "account/signup.html"
    context = {}
    response = render(request, templatePath, context)
    return response

def login(request):
    try:
        pass
        if request.method == "POST":
            if "login_button" in request.POST:
                uname = request.POST['uname']
                # uname = request.POST.get('uname)
                # email = request.POST['email']
                pswd = request.POST['pswd']
                # print(uname, pswd)
                # print(request.POST)
                user = UsersTable.objects.filter(username = uname)
                    # Gets a user by username
                # user = UsersTable.objects.get(username = uname)
                    # Gets a user by username                
                # user = UsersTable.objects.filter(username = uname)[0]
                    # Get first user if multiple rows or user objects have same username. If [0] was not there it will give queryset of all rows that matches username
                # or
                # user = UsersTable.objects.filter(email = uname)

                if user:
                    password = user[0].password
                    isVerified = user[0].is_verified
                    # print(password)
                    passFlag = check_password(pswd, password)
                    verifyFlag = False
                    if isVerified:
                        verifyFlag = True
                    if passFlag and verifyFlag:
                        print("Success!")
                        request.session['user'] = user[0].id
                        request.session['email'] = user[0].email
                        request.session['username'] = user[0].username
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
                    #             "fname" : user[0].first_name,
                    #             "lname" : user[0].last_name,
                    #             "username" : user[0].username,
                    #             "email" : user[0].email
                    #         }
                    #     }
                    #     templatePath = "account/profile.html"
                    #     response = render(request, templatePath, context)
                    #     return response

                    else:
                        print("Can't Login!")
                        print("Verify email!")
                else:
                    print("Username or Email do not exist!")

                # return redirect("index")

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
        templatePath = "404.html"
    response = render(request, templatePath, context)
    return response

def logout(request):
    request.session.clear()
        # CLear Session
    return redirect('index')
