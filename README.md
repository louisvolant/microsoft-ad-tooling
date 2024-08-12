# microsoft-ad-tooling
Tooling suite to perform actions onto a Microsoft AD

## Requirements

1. First install the required packages

Python3, logging, argparse, ldap3, pyOpenSSL, pycryptodome, tabulate

````
python3 -m venv myenv
source myenv/bin/activate // on MacOS
source myenv/Scripts/activate // on Windows
pip install ldap3 pyOpenSSL pycryptodome tabulate
````

2. List users

To list the users in a given OU

First create a config.py file (or fill the one given)

Fields required are : 
````
server_name, domain, admin_username, password, base_dn, excluded_ous
````

Then execute the script using : 
````
python3 listallusers.py
````

3. User cloning

To clone a given user to a new one (keeping the groups he is in) : 
First create a config.py file (or fill the one given)

Fields required are : 
````
server_name, domain, admin_username, password, base_dn, new_user_firstname, new_user_lastname, new_user_username, new_user_domain, new_user_password, new_user_email, new_user_description
````

Then execute the script using : 
````
python3 cloneuser.py username_of_the_user_to_clone
````
