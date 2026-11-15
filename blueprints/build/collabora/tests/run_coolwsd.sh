#!/bin/bash
# start coolwsd as user cool; plain-HTTP, WOPI host 127.0.0.1 allowed (test only)
exec su -s /bin/bash cool -c '/usr/bin/coolwsd --version >/dev/null 2>&1; exec /usr/bin/coolwsd \
 --o:sys_template_path=/opt/cool/systemplate --o:child_root_path=/opt/cool/child-roots \
 --o:file_server_root_path=/usr/share/coolwsd --o:cache_files.path=/opt/cool/cache \
 --o:logging.color=false --o:logging.level=warning --o:ssl.enable=false --o:ssl.termination=false \
 --o:mount_jail_tree=false --o:net.service_root="" \
 --o:storage.wopi.host[0]=127.0.0.1 --o:storage.wopi.host[0][@allow]=true \
 --o:admin_console.username=admin --o:admin_console.password=ou-test-only \
 --o:lo_template_path=/opt/officeunbound-office \
 --o:logging.file[@enable]=true --o:logging.file.property[0]=/var/log/coolwsd.log --o:logging.file.property[0][@name]=path'
