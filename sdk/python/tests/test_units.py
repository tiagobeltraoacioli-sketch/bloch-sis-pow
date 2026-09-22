import unittest
from blochclient.units import MAX_SATS, parse_sats, bloch_to_sats


class AmountParsing(unittest.TestCase):
    def test_exact_bounds(self):
        self.assertEqual(parse_sats(str(MAX_SATS)), MAX_SATS)
        self.assertEqual(bloch_to_sats("1.00000001"), 100000001)
        with self.assertRaises(ValueError):
            parse_sats(str(MAX_SATS + 1))

    def test_rejects_unicode_and_oversized_wire_amounts(self):
        for value in ["²", "１２", "١٢", "9" * 5000, "", "01"]:
            with self.subTest(value=value[:20]), self.assertRaises(ValueError):
                parse_sats(value)

    def test_rejects_empty_and_unicode_display_amounts(self):
        for value in ["", ".", "²", "１２", "١٢"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                bloch_to_sats(value)
