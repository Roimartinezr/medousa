import whois

w = whois.whois("earlychildhoodaustralia.org.au")

print(w)                     # imprime todo el objeto
print("Country:", w.country) # a veces viene aquí
print("Org:", w.org)         # organización registrante