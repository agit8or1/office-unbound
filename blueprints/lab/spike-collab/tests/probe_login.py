import sys
import collab_lib as L
import matrix_sso as M
c = M.login("bob", L.password("bob"))
print("mxid", c.mxid, "device", c.device, "login s", c.login_seconds, "expires", c.expires_in, "refresh", bool(c.refresh))
