# Item Catalog Web App #
This web app is a project for the Udacity [FSND Course][https://www.udacity.com].

# Project Description #
This project is a RESTful web application utilizing the Flask framework which accesses a SQL database that populates categories and their items. OAuth2 provides authentication for further CRUD functionality on the application. Third party OAuth2 is implemented for Google and FaceBook Accounts.

# In This Repo #
This project has the `view` Python module *project.py* which runs the Flask application. A SQL database is created using the `model` file *database_setup.py* module and you can populate the database with test data using *categories_loader.py*. The Flask application uses stored HTML templates in the tempaltes folder to build the front-end of the application.

# Skills Used #
1. Python
2. HTML
3. CSS
4. OAuth
5. Flask Framework

# Installation #
There are some dependancies and a few instructions on how to run the application. Seperate instructions are provided to get GConnect working also.

# Dependencies #
- Vagrant
- Udacity Vagrantfile
- VirtualBox

# How to Install #
1. Install Vagrant & VirtualBox [www.vagrant.com][www.vagrant.com], [www.virtualbox.org][www.virtualbox.org]
2. Clone the Udacity Vagrantfile
3. Go to Vagrant directory and either clone this repo or download and place zip here
4. Launch the Vagrant VM (vagrant up)
5. Log into Vagrant VM (vagrant ssh)
6. Navigate to *cd/vagrant* as instructed in terminal
7. `sudo apt-get update`
8. `sudo pip install --upgrade oauth2client`
9. `sudo pip install Flask`
10. `sudo pip install passlib`
11. `sudo pip install flask-httpauth`
12. `sudo pip install request`
13. Setup application database python */item-catalog/database_setup.py*
14. Insert fake data python */item-catalog/categories_loader.py* (inser your email address used for google or facebook account to be able to do CRUD manipulation with given data.)
15. Run application using python */item-catalog/project.py*
16. Access the application locally using [http://localhost:5000][http://localhost:5000]

# Using Google Login #
To get the Google login working there are a few additional steps:

1. Go to Google Dev Console
2. Sign up or Login if prompted
3. Go to Credentials
4. Select Create Crendentials > OAuth Client ID
5. Select Web application
6. Enter name **'Item-Catalog'**
7. Authorized JavaScript origins = `'http://localhost:5000'`
8. Authorized redirect URIs = `'http://localhost:5000/login'` && `'http://localhost:5000/gconnect'`
9. Select Create
10. Copy the Client ID and paste it into the data-clientid in `login.html`
11. On the Dev Console Select Download JSON
12. Rename JSON file to `client_secrets.json`
13. Place JSON file in item-catalog directory that you cloned from here
14. Run application using python */item-catalog/app.py*

# JSON Endpoints #
The following is open to the public:

Catalog JSON: /catalog.JSON - Displays the whole catalog. Categories and all items.

