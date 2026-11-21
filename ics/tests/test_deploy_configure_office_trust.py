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


def test_opencloud_and_keycloak_trust_the_bundle_ldap_stays_strict():
    """2026-11-21: OpenCloud trusted only the deployment CA (SSL_CERT_FILE); its WOPI service answered 500 once the names served the public
    certificate. Every container that calls another name of the deployment uses trust.crt; the LDAP connection stays on the deployment CA."""
    from ics.deploy.catalog import default_dir as catalog_dir
    env = (catalog_dir() / "templates" / "files" / "opencloud.env").read_text()
    assert re.search(r"^SSL_CERT_FILE=/opt/ou-tls/trust\.crt$", env, re.M)
    assert re.search(r"^OC_LDAP_CACERT=/opt/ou-tls/ca\.crt$", env, re.M)
    idy = (catalog_dir() / "components" / "identity.yaml").read_text()
    assert "KC_TRUSTSTORE_PATHS: /opt/ou-tls/trust.crt" in idy
