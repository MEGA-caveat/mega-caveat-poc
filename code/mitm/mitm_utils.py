# utilities for mitmproxy script

import json

from mitmproxy import http

from attack_utils import url_decode, blocklen, getBlocks, aes_encrypt

#
# must be set before running the attack
#

MASTER_KEY = ""  # extracted from a test account, only used to simulate the ECB oracle

#
# parameters
#

HEADERS = {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Cache-Control": "no-store"}

#
# utilites
#

def make_response(content, headers=HEADERS):
    return http.Response.make(200, json.dumps(content), headers)

def get_two_ecb_blocks(ecbOracle, block0: bytes, block1: bytes) -> (bytes, bytes):
    """
    Shorthand for using the 2-block ECB oracle for non-contiguous input blocks.
    """

    ciphertext = ecbOracle.call(block0 + block1)
    return getBlocks(ciphertext, 0), getBlocks(ciphertext, 1)

def get_one_ecb_block(ecbOracle, block: bytes) -> bytes:
    """
    Shorthand for using the 2-block ECB oracle for a single input block. 
    (Costs more than necessary.)
    """

    ciphertext = ecbOracle.call(block + block)
    return getBlocks(ciphertext, 0)

def get_many_ecb_blocks(ecbOracle, blocks: bytes) -> bytes:
    """
    Shorthand for using the 2-block ECB oracle for a contiguous sequence of input blocks.
    """

    ciphertext = b''

    num_blocks = blocklen(blocks)
    for i in range(num_blocks // 2):
        ciphertext += ecbOracle.call(getBlocks(blocks, 2*i, 2))
    if num_blocks % 2 != 0:
        last_block = get_one_ecb_block(ecbOracle, getBlocks(blocks, -1))
        ciphertext += last_block

    assert blocklen(ciphertext) == num_blocks
    return ciphertext

#
# simulated ECB encryption oracle
#

class EcbOracle:
    def __init__(self, master_key=MASTER_KEY):
        self.mk = url_decode(master_key)
        self.count = 0

    def call(self, plaintext):
        assert blocklen(plaintext) == 2  # the real oracle returns 2 blocks at a time
        self.count += 1

        return aes_encrypt(plaintext, self.mk)

    def getCount(self):
        return self.count