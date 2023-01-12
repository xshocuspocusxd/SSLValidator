#Author: Lukasz Podgorskli
#Version: 1.0
#Date created: 2023-01-12
#This script checks the validity of SSL certificate for multiple domains, which are read from a file

import ssl
import datetime
import socket

# Pobranie listy domen z pliku
with open("domains.txt") as f:
    domains = f.read().splitlines()

for domain in domains:
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(), server_hostname=domain)
        conn.connect((domain, 443))
        certificate = conn.getpeercert(binary_form=True)
        x509 = ssl.DER_cert_to_PEM_cert(certificate)

        from OpenSSL import crypto
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, x509)
        expiration_date = datetime.datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')

        if datetime.datetime.now() > expiration_date:
            print(f"Certyfikat dla domeny {domain} jest nieaktualny.")
        else:
            days_to_expiration = (expiration_date - datetime.datetime.now()).days
            print(f"Certyfikat dla domeny {domain} jest aktualny, ważność kończy się za {days_to_expiration} dni. Data wygaśnięcia {expiration_date}")
    except Exception as e:
        print(f"Wystąpił błąd podczas sprawdzania certyfikatu dla domeny {domain}: {e}. Program zostanie zakończony.")
        exit()