"""CLI : python -m audit_web <url>

Audit défensif en lecture seule : en-têtes de sécurité HTTP + expiration du
certificat TLS. À utiliser uniquement sur des sites dont vous êtes
propriétaire ou que vous êtes explicitement autorisé à auditer.
"""

from __future__ import annotations

import argparse
import sys
import urllib.request
from urllib.parse import urlparse

from . import __version__
from .entetes import analyser_entetes, resume
from .tls import inspecter_certificat

AVERTISSEMENT = (
    "Cet outil ne fait que des requêtes de lecture standards (comme un navigateur).\n"
    "Utilisez-le uniquement sur des sites dont vous êtes propriétaire ou que vous\n"
    "êtes explicitement autorisé à auditer.\n"
)


def _recuperer_entetes(url: str, delai_s: float) -> tuple[dict[str, str], str]:
    requete = urllib.request.Request(url, method="GET", headers={"User-Agent": "audit-web/0.1"})
    with urllib.request.urlopen(requete, timeout=delai_s) as reponse:
        entetes = dict(reponse.getheaders())
        hote_final = urlparse(reponse.geturl()).hostname or urlparse(url).hostname
    return entetes, hote_final


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="audit_web", description=__doc__)
    p.add_argument("url", help="URL à auditer, ex : https://exemple.fr")
    p.add_argument("--delai", type=float, default=5.0, help="délai d'attente en secondes (défaut : 5)")
    p.add_argument("--version", action="version", version=__version__)
    args = p.parse_args(argv)

    print(AVERTISSEMENT)
    url = args.url if args.url.startswith(("http://", "https://")) else f"https://{args.url}"
    hote = urlparse(url).hostname

    try:
        entetes, hote_final = _recuperer_entetes(url, args.delai)
    except Exception as e:
        print(f"Erreur lors de la requête HTTP : {e}", file=sys.stderr)
        return 1

    constats = analyser_entetes(entetes)
    r = resume(constats)
    print(f"En-têtes de sécurité — {url}")
    for c in constats:
        marque = {"ok": "OK", "faible": "ATTENTION", "manquant": "MANQUANT"}[c.niveau]
        print(f"  [{marque:9}] {c.entete} : {c.message}")
    print(f"Résumé : {r['ok']} ok, {r['faible']} à surveiller, {r['manquant']} manquant(s)\n")

    if url.startswith("https://"):
        try:
            info = inspecter_certificat(hote_final or hote)
            print(f"Certificat TLS — {info.hote}")
            print(f"  émetteur : {info.emetteur}")
            print(f"  expire le : {info.expire_le.date()} ({info.jours_restants} jours restants)")
            if info.alerte:
                print(f"  ATTENTION : {info.alerte}")
        except Exception as e:
            print(f"Impossible de vérifier le certificat TLS : {e}", file=sys.stderr)
    else:
        print("Site en HTTP : pas de certificat TLS à vérifier (recommandé : migrer en HTTPS).")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
