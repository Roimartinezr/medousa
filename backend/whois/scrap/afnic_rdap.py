import httpx
import logging
from typing import Dict, Any, Optional, List

# Configure logger
logger = logging.getLogger(__name__)

class AfnicRDAP:
    """
    Scraper for .fr domains using the official AFNIC RDAP API.
    RDAP (Registration Data Access Protocol) provides structured JSON data.
    """
    def __init__(self):
        """
        Initializes the scraper with a base URL and necessary headers.
        """
        self.base_url = "https://rdap-2t.nic.fr/domain/"
        self.headers = {
            "accept": "application/json, text/plain, */*",
            "accept-language": "es-ES,es;q=0.9",
            "origin": "https://whois.afnic.fr",
            "priority": "u=1, i",
            "referer": "https://whois.afnic.fr/",
            "sec-ch-ua": '"Chromium";v="140", "Not=A?Brand";v="24", "Opera";v= "124"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "cross-site",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 OPR/124.0.0.0"
        }

    def _get_vcard_property(self, vcard: List, property_name: str) -> Optional[str]:
        """Safely extracts a property from a jCard (vCard in JSON) array."""
        if not isinstance(vcard, list) or len(vcard) < 2:
            return None
        for item in vcard[1]:
            if item[0] == property_name:
                return item[3]
        return None

    def _parse_rdap_response(self, rdap_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parses the raw RDAP JSON response into a standardized format.
        """
        domain_name = rdap_data.get("ldhName", "").lower()
        
        # Initialize the structure for parsed fields
        fields = {
            "domain_name": domain_name,
            "registrant": None,
            "registrant_name": None,
            "registrar": None,
            "emails": [],
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "name_servers": [],
            "status": []
        }

        # --- Extract dates from events ---
        for event in rdap_data.get("events", []):
            action = event.get("eventAction")
            date = event.get("eventDate")
            if action == "registration":
                fields["creation_date"] = date
            elif action == "expiration":
                fields["expiration_date"] = date
            elif action == "last changed":
                fields["updated_date"] = date

        # --- Extract entities (registrant, registrar) and emails ---
        all_emails = set()
        for entity in rdap_data.get("entities", []):
            roles = entity.get("roles", [])
            vcard = entity.get("vcardArray")
            
            if vcard:
                email = self._get_vcard_property(vcard, "email")
                if email:
                    all_emails.add(email)

                if "registrant" in roles:
                    fields["registrant"] = self._get_vcard_property(vcard, "fn") or self._get_vcard_property(vcard, "org")
                    fields["registrant_name"] = self._get_vcard_property(vcard, "fn")

                if "registrar" in roles:
                    fields["registrar"] = self._get_vcard_property(vcard, "fn")

        fields["emails"] = list(all_emails) if all_emails else None

        # --- Extract nameservers ---
        nameservers = [ns.get("ldhName") for ns in rdap_data.get("nameservers", []) if ns.get("ldhName")]
        fields["name_servers"] = " ".join(sorted(nameservers)) if nameservers else None
        
        # --- Extract status ---
        status = rdap_data.get("status", [])
        fields["status"] = ", ".join(status) if status else None

        return fields


    async def get_whois(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Fetches and parses WHOIS data for a given domain.

        Args:
            domain: The domain name to query (e.g., "orange.fr").

        Returns:
            A dictionary containing the parsed WHOIS data,
            or None if an error occurs.
        """
        if not domain:
            logger.error("AFNIC RDAP: Domain cannot be empty.")
            return None

        url = f"{self.base_url}{domain.strip().lower()}"
        logger.debug(f"Querying AFNIC RDAP for: {domain} at {url}")

        async with httpx.AsyncClient(http2=True, follow_redirects=True, timeout=15.0) as client:
            try:
                response = await client.get(url, headers=self.headers)

                if response.status_code == 200:
                    logger.info(f"Successfully retrieved WHOIS for {domain} from AFNIC RDAP.")
                    raw_data = response.json()
                    return self._parse_rdap_response(raw_data)
                
                elif response.status_code == 404:
                    logger.warning(f"Domain {domain} not found via AFNIC RDAP (HTTP 404).")
                    return {"error": "Domain not found", "domain": domain, "status_code": 404}
                
                else:
                    logger.error(
                        f"AFNIC RDAP query for {domain} failed with status code: {response.status_code}. "
                        f"Response: {response.text}"
                    )
                    return {
                        "error": "Failed to retrieve WHOIS data",
                        "domain": domain,
                        "status_code": response.status_code,
                        "response_body": response.text
                    }

            except httpx.RequestError as e:
                logger.error(f"An HTTPX request error occurred while querying AFNIC RDAP for {domain}: {e}")
                return {"error": "HTTP request failed", "domain": domain, "details": str(e)}
            
            except Exception as e:
                logger.error(f"An unexpected error occurred in AfnicRDAP for {domain}: {e}", exc_info=True)
                return {"error": "An unexpected error occurred during parsing", "domain": domain, "details": str(e)}

async def main(domain: str) -> Optional[Dict[str, Any]]:
    """
    Main function to instantiate and run the scraper for a domain.
    """
    scraper = AfnicRDAP()
    return await scraper.get_whois(domain)

if __name__ == '__main__':
    import asyncio
    import json
    import sys

    # Set event loop policy for Windows if applicable
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    async def test():
        # Domain to test, passed as a command-line argument or use a default
        test_domain = sys.argv[1] if len(sys.argv) > 1 else "orange.fr"
        print(f"Testing AFNIC RDAP scraper for domain: {test_domain}...")
        
        result = await main(test_domain)
        
        if result:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print("Scraper returned no result.")

    try:
        asyncio.run(test())
    except KeyboardInterrupt:
        print("\nTest interrupted by user.")
