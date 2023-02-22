# README

This documents the proof-of-concept code for the attacks described in the paper "Caveat Implementor! Key Recovery Attacks on MEGA". See [the website](https://mega-tera.github.io).

:warning: This code is only intended to make our attacks reproducible. You should never run the attacks against any account that you do not own. Furthermore, it is the responsibility of the person executing the code in this repo to ensure they never put any disproportionate stress on MEGA's infrastructure, e.g., by spamming login requests. The code is provided without any guarantees and the person running the code bears all responsibility.

Parts of the code are based on the previous [Mega-Awry PoC code](https://github.com/Mega-Awry/attacks-poc).

## Overview

The code is organised in three parts:
1. [ECB encryption oracle](code/ecb-oracle): verify the existence of the oracle in MEGAdrop.
2. [MitM key-overwriting attacks](code/mitm): the two attacks described in the paper allow to decrypt a given AES-ECB block.
3. [RSA key recovery](code/rsa): demonstrate how to extract the full RSA key using lattice techniques. 

## ECB encryption oracle (Section 2.2)

### Simple

Follow the instructions below to verify that there is an oracle for encrypting two arbitrary blocks with AES-ECB under the master key.

Requirements:

- Initialize the [Mega-Awry PoC code](https://github.com/Mega-Awry/attacks-poc) that is included in the `mega_awry_poc/` folder.

How to reproduce:

1. Create a victim account with some username hereafter referred to as `USER`.
2. Create a folder in that account and activate MegaDrop for that folder.
3. Open the developer tools and monitor the network requests.
3. Find the private key material for `USER` by inspecting your local client (more information [is in the submodule README](https://github.com/Mega-Awry/attacks-poc), you need some IT skills to inspect the internal state of your local Mega client). Enter this key material in [acc_info.py](code/ecb-oracle/acc_info_template.py). Follow the instructions in that file.
4. Open a private browser window and upload a file. The encryption of the key picked locally by your browser is transmitted in the last POST request. Commands have JSON format (cf. [MEGA's developer documentation](https://mega.io/doc)). We are looking for a command of type `"pp"`, where the encrypted key is stored (after some nesting) with the JSON key `"k"`).
5. In the network requests for the cloud of `USER`, there is a POST request that pings for new file. You find a resonse command of type `"a": "t"` containing the RSA-encrypted key that you found in step 4.
6. The POST request directly after the one above should contain a command `"a": "k"` that updates the file key and has `"nk"` set to the AES-encrypted version of the node key encapsulated with the RSA key.
7. Add the RSA-encrypted and AES-encrypted keys to [ecb-oracle/ecb-oracle.py](code/ecb-oracle/ecb-oracle.py) (follow the comments in the file) and run `python3 ecb-oracle.py`. This should verify that the two encryptions contain the same key, using the key material of `USER` that you entered previously.

### Advanced

The instructions below show how one can achieve the ECB oracle without the user needing to set up a MEGAdrop folder. This requires a bit more sophisticated setup.

Requirements:

- [mitmproxy 8.1](https://mitmproxy.org/)

How to reproduce:

1. Start the MitM proxy with our script: `mitmproxy -s ecb_oracle_mitmproxy.py`.
2. Press `B` to start a browser attached to the proxy.
3. Navigate to [mega.nz](https://mega.nz) and log into your account.
4. Observe the dev tools and look at the requests. You might need to change the `sn` value in the hardcoded response in [ecb_oracle_mitmproxy.py](code/ecb-oracle/ecb_oracle_mitmproxy.py) to your session value.
5. Check the log file `mitmproxy.log` (written to the folder from which you run `mitmproxy`) for the output of the ECB reencryption.
6. You can verify them with [ecb-oracle/ecb-oracle.py](code/ecb-oracle/ecb-oracle.py) for your private key values.
    - In that case, you also need to change the RSA-encrypted ciphertext in the mitmproxy script to one encrypted for your account's public key.

## MitM attacks (Section 3 and 4)

Here are the common requirements to run both attacks in a TLS-MitM setting, which is meant to simulate an adversarial server. Both the attack and the victim session can run on the same machine.

Requirements for the attack:

- Python 3.9+
- [SageMath 9.6](https://doc.sagemath.org/html/en/installation/index.html)
- PyCryptodome
- [mitmproxy 8.1](https://mitmproxy.org/)

Note that this setup requires that SageMath is accessible to the main Python installation.

Requirements for the victim session:

- [MEGA webclient v4.21.4](https://github.com/meganz/webclient/tree/v4.21.4) with the included `webclient-diff.patch` applied.
- browser configured to connect to mitmproxy (see [docs](https://docs.mitmproxy.org/stable/overview-getting-started/#configure-your-browser-or-device)).
- [Selenium WebDriver](https://www.selenium.dev/documentation/webdriver/getting_started/) for Python and Firefox. (Optional, only required for full automation with [victim.py](code/mitm/victim.py).)

The webclient was only modified to make it simpler to demonstrate the attack by repeating login attempts. No other modifications were made.

Tested on Arch Linux.

### Configuration

There are several parameters in the main file [mitm.py](code/mitm/mitm.py):

- `WHICH_ATTACK` is `1` for the first attack (based on modular inverse computation) and `2` for the second attack (based on small subgroups).
- `VERSION` is either `'simple'` or `'full'`, as described in the paper. The first attack offers both, the second attack implements only the `'full'` version.
- `WHICH_BLOCK` is the index of the AES-ECB block of `privk` the attack should recover, e.g. `0` for the first block.
- `LOCAL = True` completely shuts out the real MEGA servers, using previously captured requests. The data for this must be given in [mitm.py](code/mitm/mitm.py) (the variables prefixed with `LOCAL_`). If `LOCAL = False`, the proxy first intercepts the authentication request and then starts the attack. The non-local version lets through a small number of requests that preceed the authentication request to the real MEGA servers.
- `STATS = True` runs the attack in automated mode, starting a victim client session with Selenium, and collects statistics about the number of oracle calls. The test session's username and password must be filled in as `UNAME` and `PW` in [victim.py](code/mitm/victim.py). Fully implemented only for the first attack with `LOCAL = True`.

Both attacks make use of a simulated ECB oracle, however this is separate from the main attack code and only ever called as a black box. For this, fill in `MASTER_KEY` in [mitm_utils.py](code/mitm/mitm_utils.py) for the chosen test session.

The webclient is assumed to run at https://webclient.local/login: if this is different, change the URL in [victim.py](code/mitm/victim.py).

### How to run

If `STATS = True` and `LOCAL = True`, do the following:

1. Replace the `LOCAL_`-prefixed values in [mitm.py](code/mitm/mitm.py) with the ones captured from an authentication request with that account.
2. Run the proxy via `mitmdump -q -s ./mitm.py`. When the precomputation completes, a new instance of Firefox should launch automatically and the attack begins to run.

If `STATS = False` and `LOCAL = True`, do the following:

1. Replace the `LOCAL_`-prefixed values in [mitm.py](code/mitm/mitm.py) with the ones captured from an authentication request with that account.
2. Run the proxy via `mitmdump -q -s ./mitm.py`.
3. When "Mitm initialisation done" appears, run `python3 victim.py` -- from now on the attack runs automatically.

If `LOCAL = False`, do the following:

1. Run the proxy via `mitmdump -q -s ./mitm.py`.
2. When "Mitm initialisation done" appears, log in at https://mega.nz/login -- this is only to let the proxy capture one legitimate request.
3. When "Attack initialisation done" appears, run `python3 victim.py` -- from now on the attack runs automatically.

Occasionally, the webclient might get stuck on "Requesting account data...", but it can be restarted by restarting the victim session without interfering with the attack.

### Attack 1

This attack exists in the `'simple'` block-aligned form as well as the `'full'` form. As it runs, you should be able to observe it recovering the target block modulo each small prime in turn.

### Attack 2

This attack only exists in the`'full'` form, which has a more efficient precomputation phase. This attack has a longer runtime than the first. As it runs, you should be able to observe when it hits the correct x value as well as the disambiguation for t values.

Note that the implementation for the second attack is not as stable as the one for the first and some runs may fail to recover the correct plaintext. This is due to the interaction of the webclient and the proxy, not the algorithm. The client sends repeated requests that sometimes get batched, which complicates the handling on the proxy side since the attack is adaptive. In some cases this results in the attack associating a signal from the error oracles with the wrong x or t value. However, this failure is detectable (since we have access to an ECB encryption oracle and can check the result). Even if the result is incorrect, it is usually only wrong in a single x or t value. Upon detection of failure it would therefore be possible to re-check each (x,t) pair that was used via extra queries, identify the one that was wrong, and re-run only the part of the attack needed to correct the value. (Note that this last suggestion was not fully implemented yet.)

## RSA key recovery (Section 5)

The file [poc.py](code/rsa/poc.py) provides the code for the experiment verifying the success rate of recovering `q` from the private key using four blocks extracted with our MitM attacks.