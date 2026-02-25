import whois
from email_validator import validate_email, caching_resolver, EmailNotValidError

"""w = whois.whois("bancosantander.com")

print(w)                     # imprime todo el objeto
print("Country:", w.country) # a veces viene aquí
print("Org:", w.org)"""         # organización registrante

def validate_mail(mail):
    try:
        resolver = caching_resolver(timeout=10)

        emailinfo = validate_email(mail, dns_resolver=resolver, check_deliverability=False)
        email = emailinfo.normalized
        return email

    except EmailNotValidError as e:
        print(f"Invalid email: {str(e)}")
        return None

print(validate_mail("customer@bancosantander.com"))