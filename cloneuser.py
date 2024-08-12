#cloneuser.py

import logging
import argparse
from ldap3 import Server, Connection, ALL, NTLM, Tls
import ssl
from config import server_name, domain, admin_username, password, base_dn
from config import new_user_firstname, new_user_lastname, new_user_username, new_user_domain, new_user_password, new_user_email, new_user_description
import re

attributes = ['sAMAccountName', 'givenName', 'sn', 'distinguishedName', 'mail', 'description', 'memberOf']

# README
# execute with
# python3 -m venv myenv
# source myenv/bin/activate # on MacOS
# source myenv/Scripts/activate # on Windows
# pip install ldap3 pyOpenSSL pycryptodome
# create a file config.py containing the following fields : 
# server_name, domain, admin_username, password, base_dn, new_user_firstname, new_user_lastname, new_user_username, new_user_domain, new_user_password, new_user_email, new_user_description
# To execute : 
# python3 cloneuser.py username_of_the_user_to_clone
# Once finished, simply desactivate the virtual environment using "deactivate"

def extract_user_dn(input_user):
    # Using a regular expression to extract parts containing 'OR' and 'DC'
    pattern = r"(OU=[^,]+|DC=[^,]+)"
    matches = re.findall(pattern, input_user.distinguishedName.value)
    # Join results with a comma
    result = ",".join(matches)
    logging.info('OU/DC extracted: {0}'.format(result))
    return result

def do_copy_user(connexion, input_user_to_clone):

    input_user_dn = extract_user_dn(input_user_to_clone)

    # New user information
    new_user_cn = f'{new_user_firstname} {new_user_lastname}'
    new_user_dn = f'CN={new_user_cn},{input_user_dn}'
    new_user_attributes = {
        'givenName': new_user_firstname,
        'sn': new_user_lastname,
        'sAMAccountName': new_user_username,
        'userPrincipalName': new_user_username + '@' + new_user_domain,
        'mail': new_user_email,
        'description': new_user_description,
        'userPassword': new_user_password,
        'unicodePwd': ('"' + new_user_password + '"').encode('utf-16-le'),
        'distinguishedName': new_user_dn
    }

    # Copy other existing user attributes (if any)
    for attr in input_user_to_clone.entry_attributes:
        if attr not in new_user_attributes:
            new_user_attributes[attr] = input_user_to_clone[attr].values

    logging.info('User to create: new_user_dn:{0}'.format(new_user_dn))
    logging.info('User to create: new_user_attributes:{0}'.format(new_user_attributes))
    
    # Creation of the new user (commented to let operator decide if that's fine for him)
    """connexion.add(new_user_dn, ['user'], new_user_attributes)

    if connexion.result['result'] == 0:
        logging.info('New user created successfully.')
    else:
        logging.error('Error creating new user :{0}'.format(connexion.result['description']))
    """

def do_search_user(connexion, input_username):

    search_filter = f'(sAMAccountName={input_username})'

    logging.info('Calling AD with parameters : base_dn:{0} ans search_filter:{1}, attributes:{2}'.format(base_dn, search_filter, attributes))

    # Finding the Existing User and getting its attributes
    connexion.search(search_base=base_dn, search_filter=search_filter, attributes=attributes)
    if connexion.entries:
        existing_user = connexion.entries[0]
        logging.info('User to clone : {0}'.format(existing_user))

        return existing_user

    else:
        logging.info('Existing user not found.')


def main():

    parser = argparse.ArgumentParser(description='Retrieve user to clone.')
    parser.add_argument('user_to_clone', type=str, help='The user you wish to clone')
    args = parser.parse_args()

    # Configuration TLS
    tls_configuration = Tls(validate=ssl.CERT_NONE)

    # Connection to the LDAPS server
    server = Server(server_name, get_info=ALL, tls=tls_configuration)
    conn = Connection(server, user=f'{domain}\\{admin_username}', password=password, authentication=NTLM)

    # Checking the connection
    if not conn.bind():
        logging.info('Connection error :', conn.last_error)
    else:
        logging.info('Connection successful')

        existing_user = do_search_user(conn, args.user_to_clone)

        if existing_user:
            do_copy_user(conn, existing_user)

        # Closing the connection
        conn.unbind()


if __name__ == '__main__':
    ## Initialize logging before hitting main, in case we need extra debuggability
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(funcName)s - %(levelname)s - %(message)s')
    main()
