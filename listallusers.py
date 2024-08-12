#listallusers.py

import logging
from ldap3 import Server, Connection, ALL, NTLM, Tls
import ssl
from config import server_name, domain, admin_username, password, base_dn, excluded_ous
from tabulate import tabulate
import re

search_filter = '(&(objectClass=user)(objectCategory=person))'
attributes = ['sAMAccountName', 'givenName', 'sn', 'distinguishedName', 'mail', 'description', 'memberOf']

# README
# execute with
# python3 -m venv myenv
# source myenv/bin/activate # on MacOS
# source myenv/Scripts/activate # on Windows
# pip install ldap3 pyOpenSSL pycryptodome tabulate
# create a file config.py containing the following fields : server_name, domain, admin_username, password, base_dn, excluded_ous
# python3 listallusers.py 
# Once finished, simply desactivate the virtual environment using "deactivate"

def is_filtered_OU(input_ou_list):
    isFiltered = False
    for element in excluded_ous:
        if element in input_ou_list:
            isFiltered = True
            break
    return isFiltered

def do_search(connexion):

    logging.info('Calling AD with parameters : base_dn:{0} ans search_filter:{1}, attributes:{2}'.format(base_dn, search_filter, attributes))

    # User search
    connexion.search(search_base=base_dn, search_filter=search_filter, attributes=attributes)

    # Results display
    table_data = []
    for entry in connexion.entries:
        username = entry.sAMAccountName.value
        first_name = entry.givenName.value
        last_name = entry.sn.value
        mail = entry.mail
        description = entry.description
        distinguished_name = entry.distinguishedName.value
        #memberOf = entry.memberOf

        # Extract OUs from distinguishedName
        ou_pattern = re.compile(r'OU=([^,]+)')
        ou_list = ou_pattern.findall(distinguished_name)
        isFiltered = is_filtered_OU(ou_list)

        if not isFiltered:
            ou_list.reverse
            ou_path = '/'.join(ou_list)
            table_data.append([username, first_name, last_name, mail, description, ou_path]) # memberOf can be added but very long

    # Display the results in a Table (using Tabulate)
    headers = ['username', 'Firstname', 'Name', 'Mail', 'Description', 'OU path'] # We could add 'Groups' also but usually very long and hard to display
    print(tabulate(table_data, headers=headers, tablefmt='pretty'))


def main():
    # TLS Configuration
    tls_configuration = Tls(validate=ssl.CERT_NONE)

    # LDAPS server connexion
    server = Server(server_name, get_info=ALL, tls=tls_configuration)
    conn = Connection(server, user=f'{domain}\\{admin_username}', password=password, authentication=NTLM)

    # Connexion check
    if not conn.bind():
        logging.error('Connexion error :{0}'.format(conn.last_error))
    else:
        logging.info('Connexion successfull')

        do_search(conn)

        # Connexion closing
        conn.unbind()


if __name__ == '__main__':
    ## Initialize logging before hitting main, in case we need extra debuggability
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(funcName)s - %(levelname)s - %(message)s')
    main()
