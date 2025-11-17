import whois

w = whois.whois("abanca.com")

print(w)                     # imprime todo el objeto
print("Country:", w.country) # a veces viene aquí
print("Org:", w.org)         # organización registrante
