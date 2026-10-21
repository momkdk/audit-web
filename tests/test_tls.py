import unittest
from datetime import datetime, timedelta, timezone

from audit_web.tls import InfoCertificat


class TestInfoCertificatAlerte(unittest.TestCase):
    def _info(self, jours_restants: int) -> InfoCertificat:
        return InfoCertificat(
            hote="exemple.fr",
            emetteur="Test CA",
            expire_le=datetime.now(timezone.utc) + timedelta(days=jours_restants),
            jours_restants=jours_restants,
        )

    def test_expire(self):
        self.assertEqual(self._info(-1).alerte, "certificat expiré")

    def test_urgent(self):
        self.assertIn("urgent", self._info(10).alerte)

    def test_a_surveiller(self):
        self.assertIn("surveiller", self._info(20).alerte)

    def test_ok(self):
        self.assertIsNone(self._info(90).alerte)

    def test_limite_30_jours(self):
        self.assertIsNone(self._info(30).alerte)

    def test_limite_15_jours(self):
        self.assertIn("surveiller", self._info(15).alerte)


if __name__ == "__main__":
    unittest.main()
