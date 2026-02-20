import Levenshtein
from opensearchpy import OpenSearch

client = OpenSearch([{'host': 'localhost', 'port': 9200}])

def vincular_entidad(dominio_entrante):
    # 1. Normalización para la BÚSQUEDA (Sin TLD, sin guiones)
    # Ejemplo: 'pay-pal.es' -> 'paypal' | 'atheticclub' -> 'atheticclub'
    palabra_limpia = dominio_entrante.split('.')[0].lower()
    palabra_busqueda = palabra_limpia.replace("-", "")
    longitud = len(palabra_busqueda)

    # Selección de campo por longitud de la entrada
    if longitud <= 5: subcampo = "2gram"
    elif longitud <= 9: subcampo = "3gram"
    else: subcampo = "4gram"

    # 2. CAPA 1: Búsqueda por cobertura de tokens
    # OpenSearch buscará 'paypal' contra el domain_search que también está limpio de guiones
    search_query = {
        "size": 15,
        "query": {
            "match": {
                f"domain_search.{subcampo}": {
                    "query": palabra_busqueda,
                    "minimum_should_match": "60%", 
                    "operator": "or"
                }
            }
        }
    }

    res = client.search(index="known_brands_v3", body=search_query)
    candidatos = res['hits']['hits']

    if not candidatos:
        return {"entrada": dominio_entrante, "error": "No hay coincidencias de tokens"}

    # 3. CAPA 2: Refinamiento por Levenshtein (Usando la forma con guiones)
    # Comparamos 'atheticclub' (entrada) contra 'athetic-club' (ID en BD)
    mejor_match = None
    distancia_min = 99

    for c in candidatos:
        db_id = c['_id'] # 'athetic-club'
        dist = Levenshtein.distance(palabra_limpia, db_id)
        
        if dist < distancia_min:
            distancia_min = dist
            mejor_match = c

    return {
        "entrada": dominio_entrante,
        "vinculado_a": mejor_match['_id'],
        "distancia_final": distancia_min,
        "sector": mejor_match['_source']['sector']
    }

# --- PRUEBA DE FUEGO ---
# 1. 'pay-pal' (entrada) debe vincularse a 'paypal' (BD) -> Distancia 1
# 2. 'atheticclub' (phishing) debe vincularse a 'athetic-club' (legit BD) -> Distancia 1
print(vincular_entidad("pay-pa1.es"))
print(vincular_entidad("atheticclub.com"))