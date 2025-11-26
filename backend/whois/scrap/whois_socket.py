import json
import socket

# Ej: server="whois.nic.cl"
def whois_query(domain, server, port=43):
    # Conexión al servidor WHOIS
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send((domain + "\r\n").encode("utf-8"))
    response = b""
    while True:
        data = s.recv(4096)
        if not data:
            break
        response += data
    s.close()
    
    # Decodificar texto plano
    text = response.decode("utf-8", errors="ignore")
    
    # Parsear a diccionario
    result = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip().lower().replace(" ", "_")   # normaliza claves
            value = value.strip()
            result[key] = value
    
    # Convertir a JSON
    return result
