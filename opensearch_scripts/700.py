import os
from opensearchpy import OpenSearch, helpers

# Configuración del cliente
client = OpenSearch([{'host': 'localhost', 'port': 9200}])

# Definición de ruta y archivos
path = "data"  # Cambia esto por tu ruta real
archivos = [
    'banca.txt', 'cripto.txt', 'logistica.txt', 
    'software.txt', 'salud.txt', 'publico.txt', 'energia.txt'
]

def generar_datos(directorio, lista_archivos):
    for nombre_archivo in lista_archivos:
        sector = nombre_archivo.replace('.txt', '')
        full_path = os.path.join(directorio, nombre_archivo)
        
        if not os.path.exists(full_path):
            print(f"Archivo no encontrado: {full_path}")
            continue

        with open(full_path, 'r', encoding='utf-8') as f:
            for linea in f:
                dominio = linea.strip().lower()
                if dominio:
                    yield {
                        "_index": "known_brands_v3",
                        "_id": dominio,
                        "_source": {
                            "sector": sector,
                            "known_domains": [],
                            "owner_terms": [],
                            "domain_search": dominio
                        }
                    }

# Ejecución del bulk
try:
    response = helpers.bulk(client, generar_datos(path, archivos))
    print(f"Ingesta completada: {response[0]} registros procesados.")
except Exception as e:
    print(f"Error en el proceso bulk: {e}")