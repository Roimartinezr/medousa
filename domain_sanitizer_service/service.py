# app/services/domain_sanitizer_service/service.py

from sanitize_email import sanitize_mail

class DomainSanitizerService:

    sanitize_mail = staticmethod(sanitize_mail)