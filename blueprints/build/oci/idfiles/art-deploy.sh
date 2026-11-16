#!/bin/bash
# LAB host-side helper: deploy the two units in the proof machine through the podman.deploy_unit runbook. usage: art-deploy.sh kc|oc|status
R=${RBX:?path of the wrapper that runs rb-drive.sh in the machine}
KC=192.168.186.235:5000/ou/keycloak@sha256:a7e5003b478b41652446008c91518da42c6ec8371260b1932696ce7af3fbf684
OC=192.168.186.235:5000/ou/opencloud@sha256:8105eed9f97ab9a80fdaa47de4e8e414e592aa983a74f590d4effc00d5b8afce
case ${1:-} in
kc) $R podman.deploy_unit '{"component":"identity","name":"keycloak","type":"container-hostnet","image":"'$KC'","memory_mib":1400,
 "env":{"KC_DB":"postgres","KC_DB_URL":"jdbc:postgresql://127.0.0.1:5432/keycloak","KC_DB_USERNAME":"keycloak","KC_HOSTNAME":"https://auth.ou-lab.internal",
 "KC_HTTP_ENABLED":"true","KC_HTTP_HOST":"127.0.0.1","KC_HTTP_PORT":"8080","KC_PROXY_HEADERS":"xforwarded","KC_HEALTH_ENABLED":"true",
 "KC_TRUSTSTORE_PATHS":"/opt/ou-tls/ca.crt","KC_BOOTSTRAP_ADMIN_USERNAME":"kcadmin","JAVA_OPTS_KC_HEAP":"-XX:MaxRAMPercentage=60"},
 "secrets":[{"name":"kc-db-password","env":"KC_DB_PASSWORD"},{"name":"kc-admin-password","env":"KC_BOOTSTRAP_ADMIN_PASSWORD"}],
 "volumes":[{"name":"data","path":"/opt/keycloak/data"},{"name":"tls","path":"/opt/ou-tls","read_only":true}]}';;
oc) $R podman.deploy_unit '{"component":"files","name":"opencloud","type":"container-hostnet","image":"'$OC'","memory_mib":900,
 "env":{"OC_CONFIG_DIR":"/var/lib/opencloud-config","OC_BASE_DATA_PATH":"/var/lib/opencloud"},
 "secrets":[{"name":"ldap-bind-password","env":"OC_LDAP_BIND_PASSWORD"},{"name":"oc-admin-password","env":"OU_INIT_ADMIN_PASSWORD"}],
 "volumes":[{"name":"data","path":"/var/lib/opencloud"},{"name":"config","path":"/var/lib/opencloud-config"},{"name":"tls","path":"/opt/ou-tls","read_only":true}]}';;
status) $R podman.status '{}';;
esac
