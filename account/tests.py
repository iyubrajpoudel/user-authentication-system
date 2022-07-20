from django.test import TestCase
    #for password hashing
from django.contrib.auth.hashers import make_password, check_password

# Create your tests here.

"""
# Password Hashing (working)
from django.contrib.auth.hashers import make_password, check_password

password = "ISMT@2020"
hashed_password = make_password(password)
print(hashed_password)
fake_hashed_password = "pbkdf2_sha256$320000$6r53QxNWCD0sI03Mpzp3GS$nxl1s5NOT9CtLnVKWY208jbIO1HxUlcr1rSkmFxo="
# check_result = check_password(password,"pbkdf2_sha256$320000$6r53QxNWCD0sI03Mpzp3GS$nxl1s5NOT9CtLnVKWY208jbIO1HxUlcr1rSkmFxlapo=")
check_result = check_password(password, hashed_password)
# check_result = check_password(password, fake_hashed_password)
print(check_result)

"""

# Password Hashing (working)
from django.contrib.auth.hashers import make_password, check_password

password = "ISMT@2020"
hashed_password = make_password(password)
print(hashed_password)


def checkPassword(password):
    pswdCriterian = {
    "length_criteria":".{8,}",
    "lowercase_criteria":"[a-z]+",
    "uppercase_criteria":"[A-Z]+",
    "number_criteria":"[0-9]+",
    "symbol_criteria":"[^A-Za-z0-9]+",
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

        isValid = True     
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

def regexValid(regex, data):
    try:
        if (re.search(regex, fname)):
            return True
    except Exception as ex:
        print(ex)
