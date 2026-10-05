"""IP geolocation backed by a MaxMind-format City database (GeoLite2 or DB-IP Lite)."""

from __future__ import annotations

import ipaddress
import logging
import os
from typing import Dict, Optional

import geoip2.database
import geoip2.errors

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

UNKNOWN_LOCATION: Dict = {
    "country": None,
    "country_name": None,
    "city": None,
    "lat": None,
    "lon": None,
    "timezone": None,
    "source": "unavailable",
}


class GeoIPService:
    """Resolve attacker IPs to a location.

    When no GeoLite2 database is present this returns an explicit "unknown"
    result. It previously derived a country and coordinates from an MD5 hash
    of the IP address, which meant the threat map, the country filter and the
    "unique countries" statistic were all showing plausible-looking but
    entirely fabricated data.
    """

    def __init__(self):
        self.reader: Optional[geoip2.database.Reader] = None
        self.source = "geolite2"
        self._init_reader()

    def _init_reader(self):
        db_path = settings.GEOIP_DB_PATH
        if not os.path.exists(db_path):
            logger.warning(
                "GeoIP database not found at %s; sessions will be recorded "
                "without a location. Download GeoLite2-City from MaxMind and "
                "set GEOIP_DB_PATH.",
                db_path,
            )
            return
        try:
            self.reader = geoip2.database.Reader(db_path)
            database_type = self.reader.metadata().database_type
            # Recorded with every location so the data says which database
            # produced it; DB-IP's Lite edition reads through the same API.
            self.source = "dbip" if database_type.upper().startswith("DBIP") else "geolite2"
            logger.info("GeoIP database %s loaded from %s", database_type, db_path)
        except (OSError, ValueError) as exc:
            logger.error("Could not open GeoIP database: %s", exc)

    def lookup(self, ip_address: str) -> Dict:
        if not ip_address:
            return dict(UNKNOWN_LOCATION)

        try:
            parsed = ipaddress.ip_address(ip_address)
        except ValueError:
            return dict(UNKNOWN_LOCATION)

        if parsed.is_private or parsed.is_loopback:
            return {**UNKNOWN_LOCATION, "source": "private_address"}

        if not self.reader:
            return dict(UNKNOWN_LOCATION)

        try:
            response = self.reader.city(ip_address)
        except (geoip2.errors.AddressNotFoundError, ValueError):
            return {**UNKNOWN_LOCATION, "source": "not_found"}
        except Exception as exc:
            logger.error("GeoIP lookup failed for %s: %s", ip_address, exc)
            return dict(UNKNOWN_LOCATION)

        return {
            "country": response.country.iso_code,
            "country_name": response.country.name,
            "city": response.city.name,
            "lat": response.location.latitude,
            "lon": response.location.longitude,
            "timezone": response.location.time_zone,
            "source": self.source,
        }

    def close(self):
        if self.reader:
            self.reader.close()
            self.reader = None


geoip_service = GeoIPService()
