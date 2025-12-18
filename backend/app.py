from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
import uuid
import logging
import uvicorn
from contextlib import asynccontextmanager
from service.service import DomainSanitizerService


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.debug("DEBUG TEST: logging está activo")
print("PRINT TEST: stdout está activo")


# 1. Definición del Ciclo de Vida (Lifespan)
@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Lógica de STARTUP (Inicio) ---
    logger.info("Iniciando aplicación: Verificando índices de OpenSearch...")
    try:
        # Llamamos a tus métodos de inicialización
        DomainSanitizerService.ensure_mail_names_index()
        DomainSanitizerService.ensure_omit_words_index()
        DomainSanitizerService.ensure_known_brands_index()
        DomainSanitizerService.ensure_privacy_values_index()
        logger.info("Índices verificados con éxito.")
    except Exception as e:
        logger.error(f"Error crítico durante la inicialización de índices: {e}")
    
    yield # Aquí es donde la aplicación "corre"
    
    # --- Lógica de SHUTDOWN (Cierre) ---
    logger.info("Cerrando aplicación...")

# 2. Inicialización de FastAPI con lifespan
app = FastAPI(title="Domain Sanitizer API", lifespan=lifespan)
# Configuración de CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post('/validate')
async def validate(data: dict = Body(...)):
    email = data.get('email')
    if not email:
        raise HTTPException(status_code=400, detail="No email provided")

    try:
        # Usar el método de saneamiento
        sanitized_result = await DomainSanitizerService.sanitize_mail(email)
        logger.debug(f"Resultado obtenido para {email}: \n {sanitized_result}")

        # Aquí debes mapear sanitized_result a los campos esperados
        return {
            "request_id": str(uuid.uuid4()),
            "email": email,
            "veredict": sanitized_result.get("veredict", "valid"),  # Ajusta según tu lógica
            "veredict_detail": sanitized_result.get("veredict_detail", None),
            "company_impersonated": sanitized_result.get("company_impersonated", None),
            "company_detected": sanitized_result.get("company_detected", None),
            "confidence": sanitized_result.get("confidence", 1.0),
            "labels": sanitized_result.get("labels", []),
            "evidences": sanitized_result.get("evidences", [])
        }
    
    except Exception as e:
        logger.error(f"Error crítico procesando {email}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal processing error")

if __name__ == '__main__':
    # Uvicorn es el servidor ASGI equivalente a Waitress
    uvicorn.run(app, host='0.0.0.0', port=8000)
