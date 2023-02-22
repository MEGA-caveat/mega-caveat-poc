# Hacking the path because the mega awry PoC scripts are not a python package
import sys
sys.path.insert(0, "mega_awry_poc")

from shared.constants.mega_crypto import *
from acc_info import *


#################################
#        MegaDrop upload        #
#################################

# Grab the key that is uploaded when you use the MegaDrop feature to add a file to USER's cloud storage
# In the developer tools, it is in the last POST request that sends a JSON encoded command (type "a" set to "pp").
# The key is in the element called "k".

drop_k_enc = url_decode("<TODO>")
drop_k = rsa_decrypt(drop_k_enc[2:], sk)
print("Key chosen by uploader", drop_k[:32].hex())


#################################
#        MegaDrop receive       #
#################################

# Grab encrypted key for uploaded file in USER's cloud.
k_enc = url_decode("<TODO>")

# This should be drop_k but encrypted with AES!
k = aes_decrypt(k_enc, km)
print("file key:", k.hex())

assert drop_k[:32] == k
print("Keys are matching")
