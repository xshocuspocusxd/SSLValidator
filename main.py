import ssl
import datetime
import socket

domain = input("Podaj nazwę domeny: ")

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
        print("Certyfikat jest nieaktualny.")
    else:
        days_to_expiration = (expiration_date - datetime.datetime.now()).days
        print(f"Certyfikat jest aktualny, ważność kończy się za {days_to_expiration} dni.")
except Exception as e:
    print("Wystąpił błąd podczas sprawdzania certyfikatu:", e)