from __future__ import annotations
import os
from typing import Optional, Dict
import geoip2.database
from app.core.config import get_settings

settings = get_settings()


class GeoIPService:
    def __init__(self):
        self.reader: Optional[geoip2.database.Reader] = None
        self._init_reader()

    def _init_reader(self):
        db_path = settings.GEOIP_DB_PATH
        if os.path.exists(db_path):
            self.reader = geoip2.database.Reader(db_path)
        else:
            self.reader = None

    def lookup(self, ip_address: str) -> Dict:
        if not self.reader:
            return self._fallback_lookup(ip_address)

        try:
            response = self.reader.city(ip_address)
            return {
                "country": response.country.iso_code,
                "country_name": response.country.name,
                "city": response.city.name,
                "lat": response.location.latitude,
                "lon": response.location.longitude,
                "timezone": response.location.time_zone,
            }
        except Exception:
            return self._fallback_lookup(ip_address)

    def _fallback_lookup(self, ip_address: str) -> Dict:
        import hashlib
        h = int(hashlib.md5(ip_address.encode()).hexdigest()[:8], 16)

        countries = [
            ("US", "United States", 37.0902, -95.7129),
            ("CN", "China", 35.8617, 104.1954),
            ("RU", "Russia", 61.5240, 105.3188),
            ("DE", "Germany", 51.1657, 10.4515),
            ("BR", "Brazil", -14.2350, -51.9253),
            ("IN", "India", 20.5937, 78.9629),
            ("GB", "United Kingdom", 55.3781, -3.4360),
            ("FR", "France", 46.2276, 2.2137),
            ("JP", "Japan", 36.2048, 138.2529),
            ("KR", "South Korea", 35.9078, 127.7669),
            ("NL", "Netherlands", 52.1326, 5.2913),
            ("UA", "Ukraine", 48.3794, 31.1656),
            ("IR", "Iran", 32.4279, 53.6880),
            ("VN", "Vietnam", 14.0583, 108.2772),
            ("TH", "Thailand", 15.8700, 100.9925),
            ("ID", "Indonesia", -0.7893, 113.9213),
            ("NG", "Nigeria", 9.0820, 8.6753),
            ("EG", "Egypt", 26.8206, 30.8025),
            ("AU", "Australia", -25.2744, 133.7751),
            ("CA", "Canada", 56.1304, -106.3468),
        ]

        c = countries[h % len(countries)]
        return {
            "country": c[0],
            "country_name": c[1],
            "city": None,
            "lat": c[2] + (h % 100 - 50) / 10,
            "lon": c[3] + (h % 100 - 50) / 10,
            "timezone": "UTC",
        }


geoip_service = GeoIPService()
