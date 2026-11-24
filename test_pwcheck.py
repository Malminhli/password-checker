import unittest
from pwcheck import analyze, has_sequence


class TestAnalyze(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        self.assertEqual(analyze("password")["rating"], "Very weak")

    def test_long_mixed_password_is_strong(self):
        self.assertIn(analyze("T7#vq!Lm2@Rz9&Kp")["rating"], {"Strong", "Very strong"})

    def test_sequence_detected(self):
        self.assertTrue(has_sequence("xx1234yy"))
        self.assertTrue(has_sequence("dcba"))
        self.assertFalse(has_sequence("a1b2c3"))


if __name__ == "__main__":
    unittest.main()
