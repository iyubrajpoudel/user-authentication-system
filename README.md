---
This is a readme guide to run the project in your system.
---

---

# Install python

- Download and install python from : https://www.python.org/downloads/

- Make sure to check on "Add to path" checkbox to add python in environment variables.

- Check Python Installation
	```
	python
	```
	```
	python --version
	```

- Check pip (python package manager) installation
	```
	pip --version
	```
---

# Install 'pipenv' (virtual environment packaging tool)

- Use this command to install pipenv
	```bash
	pip install pipenv
	```

- Check pipenv Installation
	```bash
	pipenv --version
	```
---

# Extract project zip file inside any directory 
Optional step
> follow it if you've downloaded this project as a zip

---

# Open project directory after extraction in code editor (eg VS Code)

- Download & install VS Code from : https://code.visualstudio.com/
- Open project directory (directory having pipenv file) in VS code or in any terminal or shell (cmd/powershell in windows)

---

# Clone / Recreate virtual environment (pipenv) and install all packaged dependencies required for project

- To clone / Recreate pipenv virtual environment & install all dependencies required for project like django, requests package for google recaptcha, re, json packages for regex etc which was packaged by pipenv in a pipfile.
	```bash
	pipenv install
	```

- After installation of all dependencies, activate virtual environment shell (pipenv shell) using
	```bash
	pipenv shell
	```
	> This will allow us to fire python & django command inside virtual environment.

- Run django development server (make sure your pipenv shell is activated and is in directory of manage.py file)
	```bash
	python manage.py runserver
	```
	> This will open the development server for our project  in http://127.0.0.1:8000/

- Before this create superuser to access django admin panel to look into database.
	```bash
	python manage.py createsuperuser
	```
	- give username = eg superuser1 or leave blank for setting admin,
	- give email(optional) = eg superuser1@gmail.com or leave blank for setting none
	- password = eg $uperu$er1 or we can give simple password . Its just required for accessing django admin panel
	
	- To avoid migration issues
		```bash
		py manage.py makemigrations
		```
		```bash
		py manage.py migrate
		```

- After creating superuser, use given credentials to login into django admin

> If you don't want to create new superuser use credentials username: admin & password: admin. This was pre-created superuser by me.

- Run django development server
	```bash
	python manage.py runserver 
	```
	> Go to http://127.0.0.1:8000/admin to access django admin panel
	> Go to http://127.0.0.1:8000/ to visit our project website

- Now you can explore and test the user authentication system.
	- Try all features of the system which includes: signup, form data validation, login, submit captcha before form submission, confirm email for account activation, change password, reset password

---

## Additional extensions and tools used

### VS Code Extensions :
- Python v2022.8.1 by Microsoft
- Django v1.10.0 by Baptiste Darthenay
- indent-rainbow v8.3.1 by oderwat
- Auto Close Tag v0.5.14 by Jun Han
- Auto Rename Tag v0.1.10 by Jun Han
- Code Runner v0.11.8 by Jun Han
- Auto-Open Markdown Preview v0.0.4 by hnw
- Prettier - Code formatter v9.5.0 by Prettier
- Rainbow Brackets v0.0.6 by 2gua
- Live Server v5.7.5 by Ritwick Dey
- Cobalt2 Theme Official v2.2.5 by Wes Bos

--- 
