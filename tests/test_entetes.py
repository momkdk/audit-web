import unittest

from audit_web.entetes import analyser_entetes, resume


class TestEntetes(unittest.TestCase):
    def test_tous_entetes_absents(self):
        constats = analyser_entetes({})
        r = resume(constats)
        self.assertEqual(r["manquant"], 6)
        self.assertEqual(r["ok"], 0)

    def test_entetes_presents_insensible_casse(self):
        entetes = {
            "Strict-Transport-Security": "max-age=63072000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        constats = analyser_entetes(entetes)
        r = resume(constats)
        self.assertEqual(r["ok"], 6)
        self.assertEqual(r["manquant"], 0)

    def test_cookie_sans_attributs(self):
        constats = analyser_entetes({"Set-Cookie": "session=abc123"})
        cookie_constat = [c for c in constats if c.entete == "set-cookie"][0]
        self.assertEqual(cookie_constat.niveau, "faible")
        self.assertIn("Secure", cookie_constat.message)
        self.assertIn("HttpOnly", cookie_constat.message)
        self.assertIn("SameSite", cookie_constat.message)

    def test_cookie_complet(self):
        constats = analyser_entetes({"Set-Cookie": "session=abc123; Secure; HttpOnly; SameSite=Strict"})
        cookie_constat = [c for c in constats if c.entete == "set-cookie"][0]
        self.assertEqual(cookie_constat.niveau, "ok")

    def test_cookie_partiel(self):
        constats = analyser_entetes({"Set-Cookie": "session=abc123; Secure"})
        cookie_constat = [c for c in constats if c.entete == "set-cookie"][0]
        self.assertEqual(cookie_constat.niveau, "faible")
        self.assertNotIn("Secure", cookie_constat.message.split(":")[1])  # Secure ne doit pas être listé comme manquant
        self.assertIn("HttpOnly", cookie_constat.message)

    def test_entete_server_signale(self):
        constats = analyser_entetes({"Server": "Apache/2.4.41 (Ubuntu)"})
        server_constat = [c for c in constats if c.entete == "server"][0]
        self.assertEqual(server_constat.niveau, "faible")
        self.assertIn("Apache/2.4.41", server_constat.message)

    def test_pas_de_cookie_pas_de_constat_cookie(self):
        constats = analyser_entetes({"Content-Security-Policy": "default-src 'self'"})
        self.assertFalse(any(c.entete == "set-cookie" for c in constats))


if __name__ == "__main__":
    unittest.main()
