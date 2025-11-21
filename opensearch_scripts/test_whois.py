import whois

w = whois.whois("xn--80adxhks.xn--p1ai")

print(w)                     # imprime todo el objeto
print("Country:", w.country) # a veces viene aquí
print("Org:", w.org)         # organización registrante
