"""Collabora's WOPI trust (2026-11-21: documents stayed blank after the public-certificate switch): the deployment CA plus Let's Encrypt's roots."""
import re

from ics.deploy import configure

CA = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"


def test_office_trust_is_the_deployment_ca_plus_the_public_roots():
    out = configure.office_trust(CA)
    assert out.startswith(CA) and out.count("-----BEGIN CERTIFICATE-----") == 3
    for r in configure.PUBLIC_ROOTS:
        assert open(r).read().strip() in out


def test_catalog_points_collabora_at_the_bundle():
    from ics.deploy.catalog import default_dir as catalog_dir
    y = (catalog_dir() / "components" / "office.yaml").read_text()
    assert re.search(r"OU_CA_FILE: /opt/ou-tls/trust\.crt", y)
