# -*- coding: utf-8 -*-
"""
To run:

    sage: bulk_run(2048, 2048//4-16, 1024, seed=0, correct=True,  msb=False, jobs=96, h=36)
    sage: bulk_run(2048, 2048//4-16, 1024, seed=0, correct=False, msb=False, jobs=96, h=36)

"""

from sage.all import (
    ZZ,
    RR,
    PolynomialRing,
    random_prime,
    randint,
    matrix,
    log,
    round,
    ceil,
    set_random_seed,
    inverse_mod,
    gcd,
    cputime,
)
from multiprocessing import Pool
from functools import partial

MAX_REPS = 3


def p_known_msb_instance(bits, unknown_bits=None, correct=True):
    if unknown_bits is None:
        unknown_bits = bits / 6
    while True:
        p = random_prime(2 ** (bits / 2))
        q = random_prime(2 ** (bits / 2))
        if (p * q).nbits() == bits:
            break

    a = p - (p % 2**unknown_bits)

    if not correct:
        p_ = random_prime(2 ** (bits / 2))
        a = p_ - (p_ % 2**unknown_bits)

    return p * q, a


def p_known_lsb_instance(bits, unknown_bits=None, correct=True):
    if unknown_bits is None:
        unknown_bits = bits / 6
    while True:
        p = random_prime(2 ** (bits / 2))
        q = random_prime(2 ** (bits / 2))
        if (p * q).nbits() == bits:
            break

    a = p % 2 ** (bits // 2 - unknown_bits)

    if not correct:
        p_ = random_prime(2 ** (bits / 2))
        a = p_ % 2 ** (bits // 2 - unknown_bits)

    return p * q, a


def p_known_msb_attack_simple(N, a, unknown_bits, bits=None):
    R = 2**unknown_bits
    if bits is None:
        bits = N.nbits() // 2
    A = matrix(ZZ, 3, 3)
    A[0] = [0, R * a, R**2]
    A[1] = [a, R, 0]
    A[2] = [N, 0, 0]
    A = A.LLL()

    P, x = PolynomialRing(ZZ, "x").objgen()

    f = sum(A[0, i] // R**i * x**i for i in range(3))
    r = f.roots()[0][0]

    p_ = gcd((a + r), N)
    return (1 < p_ < N), p_


def p_known_lsb_attack_simple(N, a, unknown_bits, bits=None):
    if bits is None:
        bits = N.nbits() // 2
    a_ = (inverse_mod(2 ** (bits - unknown_bits), N) * a) % N
    return p_known_msb_attack_simple(N, a_, unknown_bits, bits)


def p_known_msb_attack_full_find_h(bits, unknown_bits):

    Nbits = bits
    xbits = unknown_bits

    gamma = float(xbits) / Nbits

    P, h = PolynomialRing(RR, "h").objgen()
    u = h / 2 - 0.5

    f = gamma * h * (h - 1) - 2 * u * 0.5 * h + u * (u + 1)
    return ceil(f.roots()[1][0])


def p_known_msb_attack_full(
    N, p0, unknown_bits, h=None, u=None, block_size=2, rep=0, bits=None, verbose=False
):
    X = 2**unknown_bits

    if bits is None:
        bits = N.nbits() // 2

    if rep >= MAX_REPS:
        return False, 1

    do_rep = False
    if h is None:
        do_rep = True
        h = p_known_msb_attack_full_find_h(ceil(log(N, 2).n()), ceil(log(X, 2)).n()) + 2 * rep

    if block_size is True:
        block_size = h

    P, x = PolynomialRing(ZZ, "x").objgen()

    if u is None:
        a = 0.5
        u = ZZ(round(a * h - 1 / 2))

    if verbose:
        print(f"h: {h}, u: {u}")

    A = matrix(ZZ, h, h)
    for i in range(h):
        if i < u:
            pi = N ** (u - i) * (p0 + x) ** i
        else:
            pi = x ** (i - u) * (p0 + x) ** u
        for j in range(h):
            A[i, j] = pi[j] * X**j

    A = A.LLL()
    if block_size > 2:
        A = A.BKZ(block_size=block_size, proof=False)

    f = sum(A[0, j] // X**j * x**j for j in range(A.ncols()))
    try:
        r = f.roots()[0][0]
    except IndexError:
        r = 0

    p_ = gcd((p0 + r), N)

    if (p_ == 1 or p_ == N) and do_rep:
        return p_known_msb_attack_full(
            N,
            p0,
            unknown_bits,
            h=None,
            u=None,
            block_size=block_size,
            rep=rep + 1,
            bits=bits,
            verbose=verbose,
        )
    else:
        return (1 < p_ < N), p_


def p_known_lsb_attack_full(N, p0, unknown_bits, bits=None, **kwds):
    if bits is None:
        bits = N.nbits() // 2
    p0_ = (inverse_mod(2 ** (bits - unknown_bits), N) * p0) % N
    return p_known_msb_attack_full(N, p0_, unknown_bits, bits=bits, **kwds)


def testit(seed, bits, unknown_bits, msb=True, correct=True, **kwds):
    set_random_seed(seed)
    if msb:
        N, p0 = p_known_msb_instance(bits, unknown_bits, correct=correct)
    else:
        N, p0 = p_known_lsb_instance(bits, unknown_bits, correct=correct)
    t = cputime()
    if msb:
        res, p = p_known_msb_attack_full(N, p0, unknown_bits, **kwds)
    else:
        res, p = p_known_lsb_attack_full(N, p0, unknown_bits, **kwds)
    print(res, p)
    t = cputime(t)
    return int(res), t


def bulk_run(bits, unknown_bits, repetitions, seed=None, correct=True, msb=True, jobs=1, **kwds):
    if seed is None:
        seed = randint(2**32)

    successes = 0
    total_time = 0.0
    max_time = 0.0

    f = partial(testit, bits=bits, unknown_bits=unknown_bits, msb=msb, correct=correct, **kwds)

    if jobs == 1:
        for i in range(repetitions):
            r, t = f(seed=seed + i)
            successes += r
            total_time += t
            max_time = max(max_time, t)
    else:
        pool = Pool(jobs)
        res = pool.map(f, [seed + i for i in range(repetitions)])
        for r, t in res:
            successes += r
            total_time += t
            max_time = max(max_time, t)
    print(f"rate: {successes / repetitions}, avg t: {total_time / repetitions}, max t: {max_time}")
    return successes / repetitions, total_time / repetitions, max_time
