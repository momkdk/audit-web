"""Vérifications TLS basiques : expiration de certificat, présence HTTPS.

Utilise uniquement le module standard `ssl`/`socket` : une connexion TLS
normale, identique à celle d'un navigateur qui visite le site.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class InfoCertificat:
    hote: str
    emetteur: str
    expire_le: datetime
    jours_restants: int

    @property
    def alerte(self) -> str | None:
        if self.jours_restants < 0:
            return "certificat expiré"
        if self.jours_restants < 15:
            return f"expire dans {self.jours_restants} jour(s) : renouvellement urgent"
        if self.jours_restants < 30:
            return f"expire dans {self.jours_restants} jour(s) : à surveiller"
        return None


def inspecter_certificat(hote: str, port: int = 443, delai_s: float = 5.0) -> InfoCertificat:
    """Se connecte en TLS au serveur et lit la date d'expiration du certificat."""
    contexte = ssl.create_default_context()
    with socket.create_connection((hote, port), timeout=delai_s) as sock:
        with contexte.wrap_socket(sock, server_hostname=hote) as tls_sock:
            cert = tls_sock.getpeercert()

    expire_le = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    emetteur = dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "inconnu")
    jours_restants = (expire_le - datetime.now(timezone.utc)).days
    return InfoCertificat(hote, emetteur, expire_le, jours_restants)
