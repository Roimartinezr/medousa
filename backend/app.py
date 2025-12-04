from flask import Flask, request, jsonify
from flask_cors import CORS
import uuid

from .service.service import DomainSanitizerService
import asyncio

from waitress import serve

import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.debug("DEBUG TEST: logging está activo")
print("PRINT TEST: stdout está activo")


app = Flask(__name__)
CORS(app)

@app.route('/validate', methods=['POST'])
def validate():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'error': {'code': 400, 'message': 'No email provided'}}), 400

    # Usar el método de saneamiento
    sanitized_result = asyncio.run(DomainSanitizerService.sanitize_mail(email))

    # Aquí debes mapear sanitized_result a los campos esperados
    response = {
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

    return jsonify(response), 200

if __name__ == '__main__':
    DomainSanitizerService.ensure_mail_names_index()
    DomainSanitizerService.ensure_omit_words_index()
    DomainSanitizerService.ensure_known_brands_index()
    DomainSanitizerService.ensure_privacy_values_index()
    serve(app, host='0.0.0.0', port=8000)
