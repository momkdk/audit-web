"""Analyse des en-têtes de sécurité HTTP d'une réponse.

Chaque vérification est une recommandation de bonnes pratiques (OWASP Secure
Headers, MDN). L'absence d'un en-tête n'est pas forcément une faille : le
niveau de risque dépend du site. Ces résultats sont indicatifs et doivent
être interprétés par une personne compétente.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Constat:
    entete: str
    niveau: str  # "manquant", "faible", "ok"
    message: str


# Référence : OWASP Secure Headers Project, MDN Web Docs.
_RECOMMANDATIONS = {
    "strict-transport-security": "impose HTTPS au navigateur et limite les attaques de rétrogradation vers HTTP",
    "content-security-policy": "réduit le risque d'injection de scripts (XSS) en limitant les sources autorisées",
    "x-content-type-options": "empêche le navigateur de deviner un type de contenu différent de celui déclaré",
    "x-frame-options": "limite le risque de clickjacking (affichage du site dans un cadre invisible)",
    "referrer-policy": "limite les informations envoyées à des sites tiers via l'en-tête Referer",
    "permissions-policy": "restreint l'accès des scripts à des fonctions sensibles (caméra, micro, géolocalisation)",
}


def analyser_entetes(entetes: dict[str, str]) -> list[Constat]:
    """Analyse un dict d'en-têtes HTTP (noms insensibles à la casse) et renvoie les constats."""
    entetes_min = {k.lower(): v for k, v in entetes.items()}
    constats: list[Constat] = []

    for nom, role in _RECOMMANDATIONS.items():
        if nom not in entetes_min:
            constats.append(Constat(nom, "manquant", f"absent : {role}"))
        else:
            constats.append(Constat(nom, "ok", f"présent : {role}"))

    cookies = entetes_min.get("set-cookie", "")
    if cookies:
        manques = []
        cookie_min = cookies.lower()
        if "secure" not in cookie_min:
            manques.append("Secure")
        if "httponly" not in cookie_min:
            manques.append("HttpOnly")
        if "samesite" not in cookie_min:
            manques.append("SameSite")
        if manques:
            constats.append(
                Constat("set-cookie", "faible", f"cookie observé sans attribut(s) : {', '.join(manques)}")
            )
        else:
            constats.append(Constat("set-cookie", "ok", "cookie observé avec Secure, HttpOnly et SameSite"))

    serveur = entetes_min.get("server")
    if serveur:
        constats.append(
            Constat("server", "faible", f"en-tête Server révèle : '{serveur}' (expose la techno/version)")
        )

    return constats


def resume(constats: list[Constat]) -> dict[str, int]:
    r = {"manquant": 0, "faible": 0, "ok": 0}
    for c in constats:
        r[c.niveau] += 1
    return r
