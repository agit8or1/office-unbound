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


def test_collabora_wopi_client_trusts_the_bundle_through_ssl_cert_file():
    """Live 0.9.1 (2026-11-21): with ssl.enable=false coolwsd's WOPI client ignores ssl.ca_file_path (online cp-26.04.6-1
    StorageConnectionManager.cpp reads it only when ssl.enable=true) and trusts OpenSSL's default paths only (net/Ssl.cpp honours SSL_CERT_FILE):
    "unable to get local issuer certificate" against the gateway's deployment-CA certificate. The unit environment points them at trust.crt."""
    import os
    import sys

    from ics.deploy.catalog import load_catalog
    unit = next(a.unit for a in load_catalog().components["office"].artifacts if a.kind == "oci")
    assert unit.env["SSL_CERT_FILE"] == unit.env["OU_CA_FILE"] == "/opt/ou-tls/trust.crt"
    assert any(v.path == "/opt/ou-tls" for v in unit.volumes)                    # the file is in the mounted tls volume (office_runbooks writes it)
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
    from ou_agent import guestspec
    assert guestspec.ENVKEY_RE.match("SSL_CERT_FILE") and guestspec.ENVVAL_RE.match("/opt/ou-tls/trust.crt")   # the agent accepts it
