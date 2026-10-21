# audit-web

🔗 **Essayer en ligne, gratuitement : [momkdk.github.io/audit-web](https://momkdk.github.io/audit-web/)** (collez des en-têtes HTTP déjà récupérés)

Audit **défensif** et en **lecture seule** de la configuration de sécurité d'un site web :
en-têtes de sécurité HTTP et expiration du certificat TLS. Python pur, aucune dépendance, licence MIT.

## ⚠️ Cadre d'usage

Cet outil ne fait que des requêtes HTTP(S) standards, identiques à celles d'un navigateur qui
visite le site. Il ne tente **aucune intrusion, aucun contournement, aucune attaque**.

**Utilisez-le uniquement sur des sites dont vous êtes propriétaire, ou que vous êtes
explicitement autorisé à auditer.** Auditer un site tiers sans autorisation peut être illégal
selon les pays, même avec un outil purement passif.

## Ce qu'il vérifie

- **En-têtes de sécurité HTTP** : `Strict-Transport-Security`, `Content-Security-Policy`,
  `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`,
  attributs des cookies (`Secure`, `HttpOnly`, `SameSite`), et ce que révèle l'en-tête `Server`.
  Référence : [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/).
- **Certificat TLS** : émetteur et date d'expiration, avec alerte si l'expiration approche.

## Utilisation

```
python -m audit_web https://exemple.fr
```

Exemple de sortie :

```
En-têtes de sécurité — https://exemple.fr
  [OK       ] strict-transport-security : présent : impose HTTPS au navigateur...
  [MANQUANT ] content-security-policy : absent : réduit le risque d'injection de scripts (XSS)...
  ...
Résumé : 3 ok, 1 à surveiller, 2 manquant(s)

Certificat TLS — exemple.fr
  émetteur : Let's Encrypt
  expire le : 2027-01-15 (86 jours restants)
```

## Limites à connaître

- Un en-tête absent n'est **pas automatiquement une faille** : le niveau de risque dépend du
  site, de son contexte et de ce qu'il expose. Ces résultats sont indicatifs et doivent être
  interprétés par une personne compétente.
- L'outil ne teste pas la configuration TLS en profondeur (versions de protocole, suites de
  chiffrement) : pour cela, des outils dédiés comme testssl.sh ou le test SSL Labs de Qualys
  restent plus complets.
- Il ne remplace pas un audit de sécurité complet ni un test d'intrusion mené par un
  professionnel.

## Tests

```
python -m unittest discover -s tests -v
```

## Auteur

Mohamed Ali El Amri, développeur freelance Python et IA, Cluses (Haute-Savoie).

Licence MIT.
