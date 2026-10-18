"""
Tests for Homoglyph and Punycode Evasion Mitigation in model/features.py
"""
import pytest
from model import features as F


def test_clean_host_punycode_and_unicode():
    # Raw Cyrillic 'e' in ezpass.com
    cyrillic_ezpass = "\u0435zpass.com"
    clean = F.clean_host(cyrillic_ezpass)
    assert clean == "xn--zpass-ywe.com"

    # Already punycode
    assert F.clean_host("xn--zpass-ywe.com") == "xn--zpass-ywe.com"

    # Wildcard and www prefixes
    assert F.clean_host(f"*.www.{cyrillic_ezpass}.") == "xn--zpass-ywe.com"


def test_to_skeleton():
    # Cyrillic lookalikes
    assert F.to_skeleton("xn--zpass-ywe.com") == "ezpass.com"
    assert F.to_skeleton("\u0435zpass.com") == "ezpass.com"

    # Cyrillic 'p' in usps.com (xn--uss-1ed.com)
    assert F.to_skeleton("xn--uss-1ed.com") == "usps.com"

    # Greek lookalikes (e.g. nu for v in dmv)
    assert F.to_skeleton("dm\u03bd.gov") == "dmv.gov"

    # Fullwidth
    assert F.to_skeleton("\uff45\uff5a\uff50\uff41\uff53\uff53.com") == "ezpass.com"


def test_brand_gate_homoglyph_detection():
    # Punycode Cyrillic 'e' in ezpass.com
    passed, brand, cat = F.brand_gate("xn--zpass-ywe.com")
    assert passed is True
    assert brand == "ezpass"
    assert cat == "toll"

    # Cyrillic usps
    passed, brand, cat = F.brand_gate("xn--uss-1ed.com")
    assert passed is True
    assert brand == "usps"
    assert cat == "delivery"

    # Subdomain with punycode
    passed, brand, cat = F.brand_gate("xn--zpass-ywe.com-pay.top")
    assert passed is True
    assert brand == "ezpass"
    assert cat == "toll"


def test_official_never_matches_homoglyph():
    # Real sunpass.com is official
    assert F.is_official("sunpass.com") is True

    # Punycode lookalike is NOT official
    puny_sunpass = "s\u0578npass.com".encode("idna").decode("ascii")
    assert F.is_official(puny_sunpass) is False


def test_name_features_punycode():
    feats = F.name_features("xn--zpass-ywe.com")
    assert feats["punycode"] == 1
    assert feats["brand_any"] == 1
    assert feats["brand_toll"] == 1
    assert feats["official"] == 0
