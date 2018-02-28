# -*- coding: utf-8 -*-
"""
Created on Sat Dec 26 18:33:24 2015

@author: locksmith
"""

import sys
sys.path.append("..")
import unittest
import unittest.mock
import locationservice
import Crypto.Protocol.KDF
import Crypto.Hash.SHA256
import sqlite3
import time
from charm.schemes.abenc.dabe_aw11 import Dabe
from charm.toolbox.pairinggroup import PairingGroup
from charm.adapters.dabenc_adapt_hybrid import HybridABEncMA
import abeauthorityagent
import jsonhelper
import json
import constants
import locationserviceutility
import useragent

class TestUserAgent(unittest.TestCase):

    def setUp(self):
        """
        What to do here?
        """
        self.entityID = "gialackbar@live.com"
        self.userAgentDatabase="locationserviceusertest.db"
        self.userAgentObj = useragent.UserAgent(self.entityID, database=self.userAgentDatabase)
        self.bnonceSerialized = """{"c2": {"digest": "212dbef6aaf7418fd381a369ca0c7459681a9c94a6943b01f7e39d538c72e360", "alg": "HMAC_SHA2", "msg": "{\\"CipherText\\": \\"JXgWCSdpbHXtXF6Bf1qtOxoa5oKAjLxTRTm0cjIBAOw=\\", \\"MODE\\": 2, \\"ALG\\": 0, \\"IV\\": \\"x8FcjNtUxlYqZDNrzxelhA==\\"}"}, "c1": {"C2": {"MONCALAMARIEXPEDIA.COM.SPENDINGLIMIT.LEVEL3": {"__class__": "pairing.Element", "__pairingCurve__": "SS512", "__value__": "1:XaBbbFhUqFd0A81rLoZVMKCT7VKNo7mJ9eSYynDf1M3ai35dY1l5PhYc9V8/AYKBLrWsB+vtcB8XhutnuvqvAQA="}}, "C3": {"MONCALAMARIEXPEDIA.COM.SPENDINGLIMIT.LEVEL3": {"__class__": "pairing.Element", "__pairingCurve__": "SS512", "__value__": "1:FisLb/s7Uv3MGruWcFxThLs5BypD2B2znm4UcBUk7/dNR31R+jAw1jWNVT2G4koRz81tmPXpPlpe9A/b2JGw7gE="}}, "C1": {"MONCALAMARIEXPEDIA.COM.SPENDINGLIMIT.LEVEL3": {"__class__": "pairing.Element", "__pairingCurve__": "SS512", "__value__": "3:KgUiiBCqVch7fTw+Fun181g/u9ilpqO2r/sUTh2tsjefx0365WPEHJA/q59kxJqmF1ReRItcdFWafja77u0Qt6V7/NUkhGo3GPzwlouwnqzQmFjUfCwOuSKBwg5H/52z45huRluY/bIVnU+4BhxPflPcorVdN75+shf1EIDMh+A="}}, "C0": {"__class__": "pairing.Element", "__pairingCurve__": "SS512", "__value__": "3:QTmm4twXCkGCGKyPD6nReeXWk06z+JXDzLGnYkOsqM/J97gCGoyFTTH4Cy4j4De93Av7Sc4iGlVr/AquKPrbwSK5Is0hiCfv1S+PaKO2XgVFvqhk1DgpoJ9uX+WXEyZr4qHTw7X1qq0YnYFSrT0iuVZjRCfKafrfk/Gc7t+Cu58="}, "policy": "moncalamariexpedia.com.spendinglimit.level3"}}"""
        self.nb = b'uVP0RKb0iaUPQGNZc36EAA=='

    def test_abeDecrypt(self):
        """
        Test decryption of an ABE ciphertext.
        """
        plaintext = self.userAgentObj.abeDecrypt(json.loads(self.bnonceSerialized, cls=jsonhelper.KeyDecoder))
        self.assertEqual(plaintext, self.nb)

    def tearDown(self):
        pass

if __name__ == '__main__':
    unittest.main(verbosity=2)

