import re, sys
p, secret = sys.argv[1:3]
s = open(p).read()
s = re.sub(r'^(\s*)app_id=""', r'\1app_id = "ou-meet"\n\1allow_empty_token = false\n\1asap_accepted_issuers = { "ou-meet" }', s, count=1, flags=re.M)
s = re.sub(r'^(\s*)app_secret=""', r'\1app_secret = "' + secret + '"', s, count=1, flags=re.M)
open(p, 'w').write(s)
