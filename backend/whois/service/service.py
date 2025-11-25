#app/backend/scrap/service/service.py

from .get_whois_service import get_whois

class ScrapWhoisService:

    get_owner = staticmethod(get_whois)