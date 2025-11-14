# app/services/domain_sanitizer_service/service.py

from .sanitize_email import sanitize_mail
from .known_brands_service import *
from .mail_names_service import ensure_mail_names_index
from .omit_words_service import ensure_omit_words_index
from .privacy_values_service import ensure_privacy_values_index

class DomainSanitizerService:

    sanitize_mail = staticmethod(sanitize_mail)
    ensure_known_brands_index = staticmethod(ensure_known_brands_index)
    upsert_brand = staticmethod(upsert_brand)
    ensure_mail_names_index = staticmethod(ensure_mail_names_index)
    ensure_omit_words_index = staticmethod(ensure_omit_words_index)
    ensure_privacy_values_index = staticmethod(ensure_privacy_values_index)