# Usage: 
# rename this to acc_info.py and add the private key material of your account below.

from shared.mega_simulation import *

#################################
#              SETUP            #
#################################

# Use your own account for this, get the key information by inspecting your client.
# USER = <your user name>

# The following keys are for USER

# URL B64 encoded public key (use browser dev tools to inspect your web client)
pk_urlb64 = "<TODO>"

n, e = decode_urlb64_rsa_pubk(pk_urlb64)
pk = (n, e)

# We assume the adversary has already compromised the RSA public key of USER
q = <TODO, get from inspecting client>
p = <TODO>
d = <TODO>
u = <TODO>
sk = decode_rsa_privk((q, p, d, u))

# Master key of USER (simply the recovery code)
km = url_decode("<TODO>")

