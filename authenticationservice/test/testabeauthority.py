# -*- coding: utf-8 -*-
"""
Created on Sat Dec 26 18:33:24 2015

@author: locksmith
"""

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

class TestABEAuthority(unittest.TestCase):

    def setUp(self):
        """
        What to do here?
        """
        self.publicKeyFilename = 'test_amazonABEpublicKeys.txt'
        self.secretKeyFilename = 'test_amazonABEsecretKeys.txt'
        # Deterministic key files and dictionaries for specific tests.
        # Those were generated with the createABEAuthorityKeys. Testing the function with the deterministic keys
        # is somewhat circular, is it not.
#        self.amazonABEpublicKeysJSON = """{"AMAZON.COM.VIP.PRIME": {"__creationEpoch__": 1452118349.686599, "__expirationEpoch__": 1768522652.339575, "g^y_i": {"__pairingCurve__": "SS512", "__value__": "1:l5daRejarGdXTa7pR/yLwUlVIq7auVyyYHcPj/U2q7FFpP0G2Ab7+qbiYQjTuhXuRPJpiLAvEJrlHBFDuaP39gA=", "__class__": "pairing.Element"}, "e(gg)^alpha_i": {"__pairingCurve__": "SS512", "__value__": "3:mD7mPZ2xo8mtI4eVocrJgcad6IIqlM2HyzeSbZ/KcGxLm2Y85/9+1Yo5UMaUAfTl6tBpyXF3yi9GzweX9XMhE45Am8yO+9EehMwECR90Hudmwu8tSHmA49fCfUMCyF+QZpwlyeal/HQTgNozayQ7rMRxE8IjZybsysh8N/HYjuc=", "__class__": "pairing.Element"}}, "AMAZON.COM.SPENDINGLIMIT.LEVEL2": {"__creationEpoch__": 1452118349.686599, "__expirationEpoch__": 1768522652.339575, "g^y_i": {"__pairingCurve__": "SS512", "__value__": "1:FwpgNyjwr8mdZ9/C/Ibi1og0PDo6RzhJKlHq6wG5bbijbAouu0VNR8zTuz15rv75EMbf2+kRWITXz8ugdrK2CQE=", "__class__": "pairing.Element"}, "e(gg)^alpha_i": {"__pairingCurve__": "SS512", "__value__": "3:nf15w+A7g9SDLiR6u7aAlcnLaBqo0TAHspICxP6m4UK1CUsIPZXH53rRa7nCAoRSi9EBp7WjpY5pUszjAYsy9GgNRkaIWnnMr6Re4C4Tu7vm4vEAlRvGMVahtYBevSfB38bqoHIXmXOutlcYrKVBG5AhkSNPlBs1TqlySLiYbN8=", "__class__": "pairing.Element"}}, "AMAZON.COM.SPENDINGLIMIT.LEVEL3": {"__creationEpoch__": 1452118349.686599, "__expirationEpoch__": 1768522652.339575, "g^y_i": {"__pairingCurve__": "SS512", "__value__": "1:JxXwltQFQ8mKtXsddKEg2nfiBWBdD9Im9KqEqWhsjJI2ZqooCcb3zTi397c8vzTamgOjKQo1kpzQWYovo9mM0wA=", "__class__": "pairing.Element"}, "e(gg)^alpha_i": {"__pairingCurve__": "SS512", "__value__": "3:nC1I+jzUbhd3USBKAvWekaUTUgBRg2SKZy7MKsS0DyRdSg3pXEvBBCpAmOjHW1SeamW5D1nauwg8HnizRDi4XZOQ9nwWUU92W8TjgZTPuC87BTaZ30hF3+rfIq/xuai5xei47vEB6WeUTrkk9Aq1adXd/4+Ymt2fdq6ev8K6wrs=", "__class__": "pairing.Element"}}, "AMAZON.COM.SPENDINGLIMIT.LEVEL1": {"__creationEpoch__": 1452118349.686599, "__expirationEpoch__": 1768522652.339575, "g^y_i": {"__pairingCurve__": "SS512", "__value__": "1:N9GJyVGpnG3hCnvUT6dRQz4VBmHy09DcxWBvb0nG+OQi6Dpq8BYGYsH2tTZVBNSAWGWgsok2vrgF8WYQLUqvFAE=", "__class__": "pairing.Element"}, "e(gg)^alpha_i": {"__pairingCurve__": "SS512", "__value__": "3:HK3sXiUzenZ6gt8veRYkwCgHkOO+0w1ds10HteBK/K+IeBbjbOwpQEsFKvRjlk+HHW8ShDPk00oXSH2xAspbFXdfU9WfzhlRGJbf2CkK8iObH2gj37ChZyuuQegXQkxECFG/+O4m0M9TrZVmymEMBBrUxjDpX5PQsnN5HQ/q4lo=", "__class__": "pairing.Element"}}, "__pairingCurve__": "SS512"}"""
#        self.amazonABEsecretKeysJSON = """{"AMAZON.COM.VIP.PRIME": {"__creationEpoch__": 1452118349.686599, "__expirationEpoch__": 1768522652.339575, "alpha_i": {"__pairingCurve__": "SS512", "__value__": "0:fU3EP+jIBCraoFYspWRybyrIgAY=", "__class__": "pairing.Element"}, "y_i": {"__pairingCurve__": "SS512", "__value__": "0:AoJScIrtA5FJtL+EXYRsEke2Wp4=", "__class__": "pairing.Element"}}, "AMAZON.COM.SPENDINGLIMIT.LEVEL2": {"__creationEpoch__": 1452118349.686599, "__expirationEpoch__": 1768522652.339575, "alpha_i": {"__pairingCurve__": "SS512", "__value__": "0:GppIso8g0eobKXuHRZgr5kZCdkc=", "__class__": "pairing.Element"}, "y_i": {"__pairingCurve__": "SS512", "__value__": "0:B1YIlnqxYYfUnhDrH3D2HTMKt98=", "__class__": "pairing.Element"}}, "AMAZON.COM.SPENDINGLIMIT.LEVEL3": {"__creationEpoch__": 1452118349.686599, "__expirationEpoch__": 1768522652.339575, "alpha_i": {"__pairingCurve__": "SS512", "__value__": "0:UREyKoup2KFrIJQ/rSIMTlXv7is=", "__class__": "pairing.Element"}, "y_i": {"__pairingCurve__": "SS512", "__value__": "0:K4EjbTnuoIGpTaYQRmw6ANy4u44=", "__class__": "pairing.Element"}}, "AMAZON.COM.SPENDINGLIMIT.LEVEL1": {"__creationEpoch__": 1452118349.686599, "__expirationEpoch__": 1768522652.339575, "alpha_i": {"__pairingCurve__": "SS512", "__value__": "0:ZRLckU/0pz0e0+8iHjbKGjhYh1k=", "__class__": "pairing.Element"}, "y_i": {"__pairingCurve__": "SS512", "__value__": "0:asPHmNtT712LSmVsi3zqMr3aW2k=", "__class__": "pairing.Element"}}, "__pairingCurve__": "SS512"}"""
#        self.amazonABEsecretKeys = {'AMAZON.COM.VIP.PRIME': {"__creationEpoch__": 1452118349.686599, "__expirationEpoch__": 1768522652.339575, 'alpha_i': 715358099488517978457197426973101076617621962758, 'y_i': 14324259921192269674113299098978711845987572382}, 'AMAZON.COM.SPENDINGLIMIT.LEVEL2': {"__creationEpoch__": 1452118349.686599, "__expirationEpoch__": 1768522652.339575, 'alpha_i': 151874407647091956726782815254693800451550377543, 'y_i': 41881547586569832667602578292390245584205428703}, 'AMAZON.COM.SPENDINGLIMIT.LEVEL3': {"__creationEpoch__": 1452118349.686599, "__expirationEpoch__": 1768522652.339575, 'alpha_i': 462811735196906604120597085491172324813136981547, 'y_i': 248366485373826173788646324246250441744638851982}, 'AMAZON.COM.SPENDINGLIMIT.LEVEL1': {"__creationEpoch__": 1452118349.686599, "__expirationEpoch__": 1768522652.339575, 'alpha_i': 577028695416908858059787972051094824514200569689, 'y_i': 609519054380397399976419549970742941816358329193}, '__pairingCurve__': 'SS512'}
#        self.amazonABEpublicKeys = {'AMAZON.COM.VIP.PRIME': {"__creationEpoch__": 1452118349.686599, "__expirationEpoch__": 1768522652.339575, 'g^y_i': [7939476475865848786487953929291999811690274487843594217048190927151844765311912976403047697221917579353174969714962831247927327967616477992297329364039670, 2600332585939086062070064097640563715182702480381955720418970673360931370530204157660959283899512947514474409617257256763010705230618233365095495072810162], 'e(gg)^alpha_i': [7973754347913290317918889276060724584208151062548689402481371129441705984740185166655021473782279822739115672100119573376964286109156120396053417397788947, 7450361533134389668910378106176272593997170814366076606734157852809297107431770582045059220074635295495878127034855080936357450709363781902077434242043623]}, 'AMAZON.COM.SPENDINGLIMIT.LEVEL2': {"__creationEpoch__": 1452118349.686599, "__expirationEpoch__": 1768522652.339575, 'g^y_i': [1206730505123496234573982474553443105652998553384724625894168326326578948048735917732773748597999803593616340956920317270705935468426122039006731095422473, 7777355181108592546192197662033745115190917470031483014840377204755076365977512028169217851198816410184144632537528454547849612220127560604686961383988591], 'e(gg)^alpha_i': [8274615006780892943894260738645821099359124504035378102556431335337735298012295200236438748378546896011308457918272374100814781073372949171074860101350132, 5449637763327254521594245048216855415169859183494505165938371968707969194914066786114414089364475810772033489544976718530997347771279749588123172241698015]}, 'AMAZON.COM.SPENDINGLIMIT.LEVEL3': {"__creationEpoch__": 1452118349.686599, "__expirationEpoch__": 1768522652.339575, 'g^y_i': [2047084335578718977023968673999533692881420999998399097643634548416663374920474341980108014913159397616683364364391444808447829516517662835523252353862867, 6819800214611874275088956682716032387506996955389017464251192769690175165933226871657513037398001070955034845277413569024674146512941678935386056038637286], 'e(gg)^alpha_i': [8179647689641673741002756556064005742984504193759794539837276972873647051353796516363448339223465938260536234997626208867456195786440263796055139969185885, 7728672207848464308181073727021438438526646741350674294920260306463521111105916340281855531889409919999220939188002735222458053646977236509769908946125499]}, 'AMAZON.COM.SPENDINGLIMIT.LEVEL1': {"__creationEpoch__": 1452118349.686599, "__expirationEpoch__": 1768522652.339575, 'g^y_i': [2923452514196683517272093785155211630190412265882595022560895380642378887623668085174067137101974551072940656312240249472791581653423028656923344187862804, 8120330683190300108984204268306207590625829523394502457992094788403628979031006845854033787141920809883177373725702530910725080272138029664419844147449617], 'e(gg)^alpha_i': [1502061425743770558564455236087012684802354733693084829990741495739224682984773417717487939225247176488613036059450710667401954281707239125274332087606037, 6252038471962991643894904066646648638463324638751427465013991400713766209785483565419828959135007039327810345283814807801790565040291257461141418428523098]}, '__pairingCurve__': 'SS512'}

        self.amazonABEpublicKeysJSON = """{"AMAZON.COM.VIP.PRIME": {"g^y_i": {"__pairingCurve__": "SS512", "__value__": "1:l5daRejarGdXTa7pR/yLwUlVIq7auVyyYHcPj/U2q7FFpP0G2Ab7+qbiYQjTuhXuRPJpiLAvEJrlHBFDuaP39gA=", "__class__": "pairing.Element"}, "e(gg)^alpha_i": {"__pairingCurve__": "SS512", "__value__": "3:mD7mPZ2xo8mtI4eVocrJgcad6IIqlM2HyzeSbZ/KcGxLm2Y85/9+1Yo5UMaUAfTl6tBpyXF3yi9GzweX9XMhE45Am8yO+9EehMwECR90Hudmwu8tSHmA49fCfUMCyF+QZpwlyeal/HQTgNozayQ7rMRxE8IjZybsysh8N/HYjuc=", "__class__": "pairing.Element"}}, "AMAZON.COM.SPENDINGLIMIT.LEVEL2": {"g^y_i": {"__pairingCurve__": "SS512", "__value__": "1:FwpgNyjwr8mdZ9/C/Ibi1og0PDo6RzhJKlHq6wG5bbijbAouu0VNR8zTuz15rv75EMbf2+kRWITXz8ugdrK2CQE=", "__class__": "pairing.Element"}, "e(gg)^alpha_i": {"__pairingCurve__": "SS512", "__value__": "3:nf15w+A7g9SDLiR6u7aAlcnLaBqo0TAHspICxP6m4UK1CUsIPZXH53rRa7nCAoRSi9EBp7WjpY5pUszjAYsy9GgNRkaIWnnMr6Re4C4Tu7vm4vEAlRvGMVahtYBevSfB38bqoHIXmXOutlcYrKVBG5AhkSNPlBs1TqlySLiYbN8=", "__class__": "pairing.Element"}}, "AMAZON.COM.SPENDINGLIMIT.LEVEL3": {"g^y_i": {"__pairingCurve__": "SS512", "__value__": "1:JxXwltQFQ8mKtXsddKEg2nfiBWBdD9Im9KqEqWhsjJI2ZqooCcb3zTi397c8vzTamgOjKQo1kpzQWYovo9mM0wA=", "__class__": "pairing.Element"}, "e(gg)^alpha_i": {"__pairingCurve__": "SS512", "__value__": "3:nC1I+jzUbhd3USBKAvWekaUTUgBRg2SKZy7MKsS0DyRdSg3pXEvBBCpAmOjHW1SeamW5D1nauwg8HnizRDi4XZOQ9nwWUU92W8TjgZTPuC87BTaZ30hF3+rfIq/xuai5xei47vEB6WeUTrkk9Aq1adXd/4+Ymt2fdq6ev8K6wrs=", "__class__": "pairing.Element"}}, "AMAZON.COM.SPENDINGLIMIT.LEVEL1": {"g^y_i": {"__pairingCurve__": "SS512", "__value__": "1:N9GJyVGpnG3hCnvUT6dRQz4VBmHy09DcxWBvb0nG+OQi6Dpq8BYGYsH2tTZVBNSAWGWgsok2vrgF8WYQLUqvFAE=", "__class__": "pairing.Element"}, "e(gg)^alpha_i": {"__pairingCurve__": "SS512", "__value__": "3:HK3sXiUzenZ6gt8veRYkwCgHkOO+0w1ds10HteBK/K+IeBbjbOwpQEsFKvRjlk+HHW8ShDPk00oXSH2xAspbFXdfU9WfzhlRGJbf2CkK8iObH2gj37ChZyuuQegXQkxECFG/+O4m0M9TrZVmymEMBBrUxjDpX5PQsnN5HQ/q4lo=", "__class__": "pairing.Element"}}, "__pairingCurve__": "SS512"}"""
        self.amazonABEsecretKeysJSON = """{"AMAZON.COM.VIP.PRIME": {"alpha_i": {"__pairingCurve__": "SS512", "__value__": "0:fU3EP+jIBCraoFYspWRybyrIgAY=", "__class__": "pairing.Element"}, "y_i": {"__pairingCurve__": "SS512", "__value__": "0:AoJScIrtA5FJtL+EXYRsEke2Wp4=", "__class__": "pairing.Element"}}, "AMAZON.COM.SPENDINGLIMIT.LEVEL2": {"alpha_i": {"__pairingCurve__": "SS512", "__value__": "0:GppIso8g0eobKXuHRZgr5kZCdkc=", "__class__": "pairing.Element"}, "y_i": {"__pairingCurve__": "SS512", "__value__": "0:B1YIlnqxYYfUnhDrH3D2HTMKt98=", "__class__": "pairing.Element"}}, "AMAZON.COM.SPENDINGLIMIT.LEVEL3": {"alpha_i": {"__pairingCurve__": "SS512", "__value__": "0:UREyKoup2KFrIJQ/rSIMTlXv7is=", "__class__": "pairing.Element"}, "y_i": {"__pairingCurve__": "SS512", "__value__": "0:K4EjbTnuoIGpTaYQRmw6ANy4u44=", "__class__": "pairing.Element"}}, "AMAZON.COM.SPENDINGLIMIT.LEVEL1": {"alpha_i": {"__pairingCurve__": "SS512", "__value__": "0:ZRLckU/0pz0e0+8iHjbKGjhYh1k=", "__class__": "pairing.Element"}, "y_i": {"__pairingCurve__": "SS512", "__value__": "0:asPHmNtT712LSmVsi3zqMr3aW2k=", "__class__": "pairing.Element"}}, "__pairingCurve__": "SS512"}"""
        self.amazonABEsecretKeys = {'AMAZON.COM.VIP.PRIME': {'alpha_i': 715358099488517978457197426973101076617621962758, 'y_i': 14324259921192269674113299098978711845987572382}, 'AMAZON.COM.SPENDINGLIMIT.LEVEL2': {'alpha_i': 151874407647091956726782815254693800451550377543, 'y_i': 41881547586569832667602578292390245584205428703}, 'AMAZON.COM.SPENDINGLIMIT.LEVEL3': {'alpha_i': 462811735196906604120597085491172324813136981547, 'y_i': 248366485373826173788646324246250441744638851982}, 'AMAZON.COM.SPENDINGLIMIT.LEVEL1': {'alpha_i': 577028695416908858059787972051094824514200569689, 'y_i': 609519054380397399976419549970742941816358329193}, '__pairingCurve__': 'SS512'}
        self.amazonABEpublicKeys = {'AMAZON.COM.VIP.PRIME': {'g^y_i': [7939476475865848786487953929291999811690274487843594217048190927151844765311912976403047697221917579353174969714962831247927327967616477992297329364039670, 2600332585939086062070064097640563715182702480381955720418970673360931370530204157660959283899512947514474409617257256763010705230618233365095495072810162], 'e(gg)^alpha_i': [7973754347913290317918889276060724584208151062548689402481371129441705984740185166655021473782279822739115672100119573376964286109156120396053417397788947, 7450361533134389668910378106176272593997170814366076606734157852809297107431770582045059220074635295495878127034855080936357450709363781902077434242043623]}, 'AMAZON.COM.SPENDINGLIMIT.LEVEL2': {'g^y_i': [1206730505123496234573982474553443105652998553384724625894168326326578948048735917732773748597999803593616340956920317270705935468426122039006731095422473, 7777355181108592546192197662033745115190917470031483014840377204755076365977512028169217851198816410184144632537528454547849612220127560604686961383988591], 'e(gg)^alpha_i': [8274615006780892943894260738645821099359124504035378102556431335337735298012295200236438748378546896011308457918272374100814781073372949171074860101350132, 5449637763327254521594245048216855415169859183494505165938371968707969194914066786114414089364475810772033489544976718530997347771279749588123172241698015]}, 'AMAZON.COM.SPENDINGLIMIT.LEVEL3': {'g^y_i': [2047084335578718977023968673999533692881420999998399097643634548416663374920474341980108014913159397616683364364391444808447829516517662835523252353862867, 6819800214611874275088956682716032387506996955389017464251192769690175165933226871657513037398001070955034845277413569024674146512941678935386056038637286], 'e(gg)^alpha_i': [8179647689641673741002756556064005742984504193759794539837276972873647051353796516363448339223465938260536234997626208867456195786440263796055139969185885, 7728672207848464308181073727021438438526646741350674294920260306463521111105916340281855531889409919999220939188002735222458053646977236509769908946125499]}, 'AMAZON.COM.SPENDINGLIMIT.LEVEL1': {'g^y_i': [2923452514196683517272093785155211630190412265882595022560895380642378887623668085174067137101974551072940656312240249472791581653423028656923344187862804, 8120330683190300108984204268306207590625829523394502457992094788403628979031006845854033787141920809883177373725702530910725080272138029664419844147449617], 'e(gg)^alpha_i': [1502061425743770558564455236087012684802354733693084829990741495739224682984773417717487939225247176488613036059450710667401954281707239125274332087606037, 6252038471962991643894904066646648638463324638751427465013991400713766209785483565419828959135007039327810345283814807801790565040291257461141418428523098]}, '__pairingCurve__': 'SS512'}

        with open(self.publicKeyFilename, "wt") as pkFilename, open(self.secretKeyFilename, "wt") as skFilename:
            pkFilename.write(self.amazonABEpublicKeysJSON)
            skFilename.write(self.amazonABEsecretKeysJSON)

        self.locationServiceDatabase="locationservicetest.db"
        self.locationServiceObj = locationservice.LocationService(database=self.locationServiceDatabase)
        self.authorityDatabase = "locationserviceauthoritytest.db"
        authority = "amazon.com"
        self.abeAuthorityObj = abeauthorityagent.ABEAuthority(authority, self.secretKeyFilename, self.publicKeyFilename, database=self.authorityDatabase)

    def test_createABEAuthorityKeysFile(self):
        # Pick one authority to which some keys are to be created (one pair of keys per authority attribute).
        authority = "amazon.com"
        pairingGroup = 'SS512'
        attributes = self.locationServiceObj.getAllLikeAttributes(authority+"%")
        ABEsecretKeys = {}
        ABEpublicKeys = {}
        expirationEpoch = 1768522652.339575 # Approximately 10 years expiration.
        # Create the ABE keys for this authority.
        ABEsecretKeys, ABEpublicKeys = self.abeAuthorityObj.createABEAuthorityKeysFile(attributes=attributes,
                                                                                       pairingGroup=pairingGroup,
                                                                                       expirationEpoch=expirationEpoch)
        #print("SK\n", ABEsecretKeys, "\nPK\n", ABEpublicKeys)
        # Cannot compare charm key dictionaries directly. It seems python does not know how to compare
        # the pairing.Element objects. Copying and pasting their printout, as in the tests below, actually
        # converts the pairing.Element objects into something else (a big number?) that python knows how to
        # compare. Therefore, let us convert the charm dictionaries to JSON dictionaries and compare those.
        ABEsecretKeysJSON = json.loads(json.dumps(ABEsecretKeys, cls=jsonhelper.KeyEncoder, pairingCurve=pairingGroup))
        ABEpublicKeysJSON = json.loads(json.dumps(ABEpublicKeys, cls=jsonhelper.KeyEncoder, pairingCurve=pairingGroup))
#        print(type(ABEsecretKeysJSON))
#        print(ABEsecretKeysJSON)
#        print(ABEsecretKeys)
#        print(self.amazonABEsecretKeys)
#        print(ABEpublicKeys)
#        print(self.amazonABEpublicKeys)
        #print(ABEsecretKeysJSON == json.loads(self.amazonABEsecretKeysJSON))
        #print(ABEpublicKeysJSON == json.loads(self.amazonABEpublicKeysJSON))
        self.assertTrue(ABEsecretKeysJSON == json.loads(self.amazonABEsecretKeysJSON))
        self.assertTrue(ABEpublicKeysJSON == json.loads(self.amazonABEpublicKeysJSON))


    def test_createABEAuthorityKeys(self):
        # Pick one authority to which some keys are to be created. Expire previous keys such that the
        # first attempt to create will not find valid, existing keys in the database.
        authority = "amazon.com"
        pairingGroup = 'SS512'
        #attributes = self.locationServiceObj.getAllLikeAttributes(authority+"%")
        attributes = ["amazon.com.vip.prime"]
        #expirationEpoch = time.time() + constants.DEFAULT_AUTHORITY_KEY_EXPIRATION_SECONDS  # Expire after 1 year.
        expirationEpoch = time.time() + 20 # 10 seconds. Create quickly expiring keys such that we can test for the function finding valid existing keys, but also registering new keys in a new unit test.
        # Create the ABE keys for this authority. Assume there are no valid keys in the database yet.
#        try:
#            ABEsecretKeys, ABEpublicKeys = self.abeAuthorityObj.createABEAuthorityKeys(attributes, pairingGroup, expirationEpoch=expirationEpoch)
#        except SystemExit:
#            print("Existing keys in database.")
#        else:
#            print("Keys generated.")
#            print("SK\n", ABEsecretKeys, "\nPK\n", ABEpublicKeys)

        ABEsecretKeys, ABEpublicKeys = self.abeAuthorityObj.createABEAuthorityKeys(attributes=attributes,
                                                                                   pairingGroup=pairingGroup,
                                                                                   expirationEpoch=expirationEpoch)
        if not ABEsecretKeys or not ABEpublicKeys:
            print("Keys not created: there are valid keys into the database.")
        else:
            print("Keys successfully generated.")

        # Do it again. New keys should not be created.
        newABEsecretKeys, newABEpublicKeys = self.abeAuthorityObj.createABEAuthorityKeys(attributes=attributes,
                                                                                   pairingGroup=pairingGroup,
                                                                                   expirationEpoch=expirationEpoch)
        # Assert that the keys are in fact empty, since there are valid ones in the database.
        self.assertEqual(newABEsecretKeys, {})
        self.assertEqual(newABEpublicKeys, {})


    def test_createABEAuthorityKeysAttributesFromDatabase(self):
        # Pick one authority to which some keys are to be created. Expire previous keys such that the
        # first attempt to create will not find valid, existing keys in the database.
        # Use whatever attributes the authority has in the database.
        authority = "amazon.com"
        pairingGroup = 'SS512'
        #expirationEpoch = time.time() + constants.DEFAULT_AUTHORITY_KEY_EXPIRATION_SECONDS  # Expire after 1 year.
        expirationEpoch = time.time() + 20 # 2a0 seconds. Create quickly expiring keys such that we can test for the function finding valid existing keys, but also registering new keys in a new unit test.
        # Specify the attributes from the database. We will not allow, for now, the function to retrieve the attributes from
        # the database automatically.
        attributes = locationserviceutility.getAllEntityAttributes(authority, expirationEpoch, database=self.abeAuthorityObj.database)
        print("Attributes of entity {}:".format(authority), attributes)
        lenOfAttributesInDatabase = len(attributes)
        print("Number of attributes: ", lenOfAttributesInDatabase)
        expired = self.abeAuthorityObj.expireABEAuthorityKeys()
        # Create the ABE keys for this authority. There should be no valid keys in the database, because of the expire command before.
        ABEsecretKeys, ABEpublicKeys = self.abeAuthorityObj.createABEAuthorityKeys(attributes=attributes,
                                                                                   pairingGroup=pairingGroup,
                                                                                   expirationEpoch=expirationEpoch)
        # Assert that the keys are not empty (if we in fact have attributes in the database).
        self.assertNotEqual(ABEsecretKeys, {})
        self.assertNotEqual(ABEpublicKeys, {})

        # Number of keys should be equal to number of attributes.
        self.assertEqual(len(ABEsecretKeys), lenOfAttributesInDatabase)
        self.assertEqual(len(ABEpublicKeys), lenOfAttributesInDatabase)

        # Now let's call the same createABE function without specifying attributes. The keys are not exactly the same,
        # since there is a random component when creating keys. But the number of keys should be the same, since the number
        # of attributes will be the same.
        newABEsecretKeys, newABEpublicKeys = self.abeAuthorityObj.createABEAuthorityKeys(pairingGroup=pairingGroup, expirationEpoch=expirationEpoch)
        # There should still be those keys created earlier in the database. As such, the function should return empty dicts.
        self.assertEqual((newABEsecretKeys, newABEpublicKeys), ({}, {}))
        # Let's retrieve the keys and assert they are the same as before.
        existingABEsecretKeys, existingABEpublicKeys = self.abeAuthorityObj.getABEAuthorityKeys()
        self.assertEqual((existingABEsecretKeys, existingABEpublicKeys), (ABEsecretKeys, ABEpublicKeys))
        # Now expire the keys, create new ones, and compare the quantity with the older ones. They keys will be different
        # due to the random component.
        expired = self.abeAuthorityObj.expireABEAuthorityKeys()
        newABEsecretKeys, newABEpublicKeys = self.abeAuthorityObj.createABEAuthorityKeys(pairingGroup=pairingGroup,
                                                                                         expirationEpoch=expirationEpoch)
        self.assertEqual((len(ABEsecretKeys), len(ABEpublicKeys)), (len(newABEsecretKeys), len(newABEpublicKeys)))
        # Make sure the number of keys is the same as the number of attributes.
        self.assertEqual(len(newABEsecretKeys), lenOfAttributesInDatabase)
        self.assertEqual(len(newABEpublicKeys), lenOfAttributesInDatabase)

        # Finally, assert the new keys are in fact different than the first ones.
        self.assertNotEqual(ABEsecretKeys, newABEsecretKeys)
        self.assertNotEqual(ABEpublicKeys, newABEpublicKeys)


    def test_expireABEAuthorityKeys(self):
        """
        Let's test here whether we can expire existing, valid ABE authority keys (keys not yet expired).
        And if there are no valid keys, test whether the function returns False.
        """

        # Pick one authority to which some keys are to be created.
        authority = "amazon.com"
        pairingGroup = 'SS512'
        attributes = ["amazon.com.vip.prime"]
        #expirationEpoch = time.time() + constants.DEFAULT_AUTHORITY_KEY_EXPIRATION_SECONDS  # Expire after 1 year.
        expirationEpoch = time.time() + 2 # 2 seconds. Create quickly expiring keys such that we can test for the function finding valid existing keys, but also registering new keys in a new unit test.
        # Expire all keys from entity (must we assume here this function does actually work?).
        expired = self.abeAuthorityObj.expireABEAuthorityKeys()
        # Now insert new keys with short expirationEpoch and expire them, which should ensure a True return from function.
        ABEsecretKeys, ABEpublicKeys = self.abeAuthorityObj.createABEAuthorityKeys(attributes=attributes,
                                                                                   pairingGroup=pairingGroup,
                                                                                   expirationEpoch=expirationEpoch)
        # Should be True.
        self.assertEqual(self.abeAuthorityObj.expireABEAuthorityKeys(), 2)
        # Once all keys are expired, another call to the expire function should return zero.
        self.assertEqual(self.abeAuthorityObj.expireABEAuthorityKeys(), 0)

    def test_prorogueABEAuthorityKeys(self):
        """
        Test whether we can successfully extend the validity of existing ABE keys.

        Only valid keys should be extended. Expired keys should remain expired, and thus new ones should
        be created. Extending expired keys equals to bringing back keys from the dead, resulting in "zombie" keys.

        Should we only allow extension, or actually updating the expirationEpoch to a lower value than
        the original?
        """
        pairingGroup = 'SS512'
        attributes = ["amazon.com.vip.prime"]
        # Expire all keys from entity (must we assume here this function does actually work?).
        # Therefore, when next attempting to extend existing keys, we should be unable to.
        expired = self.abeAuthorityObj.expireABEAuthorityKeys()
        newExpirationEpoch = time.time() + 10 # Ten seconds more than now.
        expirationEpoch = time.time() + 30 # Longer than newExpirationEpoch.
        # There should be no valid keys to extend.
        self.assertEqual(self.abeAuthorityObj.prorogueABEAuthorityKeys(newExpirationEpoch = newExpirationEpoch), 0)
        # Now insert new keys with long expirationEpoch and and attempt to extend them for only 10 seconds. Since the original
        # expirationEpoch is greater than the new one, there should be no modification.
        ABEsecretKeys, ABEpublicKeys = self.abeAuthorityObj.createABEAuthorityKeys(attributes=attributes,
                                                                                   pairingGroup=pairingGroup,
                                                                                   expirationEpoch=expirationEpoch)
        # Attempt to extend existing keys. Should not update any, since original expirationEpoch is longer than newExpirationEpoch.
        self.assertEqual(self.abeAuthorityObj.prorogueABEAuthorityKeys(newExpirationEpoch = newExpirationEpoch), 0)
        newExpirationEpoch = expirationEpoch + 10 # Assure the new expiration is after the original.
        self.assertEqual(self.abeAuthorityObj.prorogueABEAuthorityKeys(newExpirationEpoch = newExpirationEpoch), 2)

    def test_getABEAuthorityKeys(self):
        """
        Test function to retrieve existing ABE authority keys.
        """

        pairingGroup = 'SS512'
        attributes = ["amazon.com.vip.prime"]
        # Expire all keys from entity (must we assume here this function does actually work?).
        self.abeAuthorityObj.expireABEAuthorityKeys()
        # Now create a pair of ABE keys.
        expirationEpoch = time.time() + 30
        ABEsecretKeys, ABEpublicKeys = self.abeAuthorityObj.createABEAuthorityKeys(attributes=attributes,
                                                                                   pairingGroup=pairingGroup,
                                                                                   expirationEpoch=expirationEpoch)
        # Now retrieve the keys from the database and compare with the newly created ones.
        retrievedABEsecretKeys, retrievedABEpublicKeys = self.abeAuthorityObj.getABEAuthorityKeys()
        self.assertEqual((ABEsecretKeys, ABEpublicKeys), (retrievedABEsecretKeys, retrievedABEpublicKeys))
        # Now expire the keys again and repeat the test. The function should return empty dicts.
        self.abeAuthorityObj.expireABEAuthorityKeys()
        retrievedABEsecretKeys, retrievedABEpublicKeys = self.abeAuthorityObj.getABEAuthorityKeys()
        self.assertEqual((retrievedABEsecretKeys, retrievedABEpublicKeys), ({}, {}))

    def test_getOrCreateABEAuthorityKeys(self):
        """
        Test the function that gets existing ABE authority keys from the database, or creates them if there
        are none (or no valid ones).
        """

        pairingGroup = 'SS512'
        attributes = ["amazon.com.vip.prime"]
        # Expire all keys from entity (must we assume here this function does actually work?).
        # The first call to the getOrCreateABEAuthorityKeys should actually create the keys, then.
        self.abeAuthorityObj.expireABEAuthorityKeys()
        # Now call the function, and new keys should be created. Test for None.
        expirationEpoch = time.time() + 30
        ABEsecretKeys, ABEpublicKeys = self.abeAuthorityObj.getOrCreateABEAuthorityKeys(attributes=attributes,
                                                                                        pairingGroup=pairingGroup,
                                                                                        expirationEpoch = expirationEpoch)
        self.assertNotEqual((ABEsecretKeys, ABEpublicKeys), ({}, {}))
        # Call the function again, the same set of keys should be returned. Some parameters will simply be ignored.
        retrievedABEsecretKeys, retrievedABEpublicKeys = self.abeAuthorityObj.getOrCreateABEAuthorityKeys(attributes=attributes,
                                                                                                          pairingGroup=pairingGroup,
                                                                                                          expirationEpoch = expirationEpoch)
        # The returned keys should be exactly the ones obtained earlier (created).
        self.assertEqual((ABEsecretKeys, ABEpublicKeys), (retrievedABEsecretKeys, retrievedABEpublicKeys))
        # Now again expire keys and call the function. The returned keys should be different than the first set.
        self.abeAuthorityObj.expireABEAuthorityKeys()
        retrievedABEsecretKeys, retrievedABEpublicKeys = self.abeAuthorityObj.getOrCreateABEAuthorityKeys(attributes=attributes,
                                                                                                          pairingGroup=pairingGroup,
                                                                                                          expirationEpoch = expirationEpoch)
        self.assertNotEqual((ABEsecretKeys, ABEpublicKeys), (retrievedABEsecretKeys, retrievedABEpublicKeys))

    def test_createABEUserKeysAttributesAsArgument(self):
        """
        Here we test the creation of ABE user keys by passing the user attributes as argument.
        By specifying attributes, the tested function will not fetch the user attributes from the database.
        """
        userEntityID = "douggiehowser@princeton.edu"
        bestBuyID = "bestbuy.com"
        amazonID = "amazon.com"
        locationServiceID = constants.ENTITY_ID_LOCATION_SERVICE
        attributesBestBuy = ["bestbuy.com.spendinglimit.level1", "bestbuy.com.vip.gold", "bestbuy.com.vip.platinum"]
        attributesAmazon = ["amazon.com.spendinglimit.level2", "amazon.com.vip.prime"]
        attributesLocationService = ["global.payment.visa", "global.payment.androidpay", "global.store.amazon.com"]
        attributes = attributesBestBuy + attributesAmazon + attributesLocationService
        expirationEpoch = time.time() + 1 * 10 # 10 seconds.
        database = self.locationServiceDatabase # Local database to use.

        # Create agent objects here, since we will have more than one authority.
        # We will use the self location Service object.
        # Pay attention into specifying all databases, such that a key does not get registered to one database,
        # but the code looks for existing keys in another database.
        bestBuyAuthority = abeauthorityagent.ABEAuthority(bestBuyID, database=database)
        amazonAuthority = abeauthorityagent.ABEAuthority(amazonID, database=database)
        # Create sets of ABE user keys per authority, Location Service included. Pass the attributes as argument.
        bestBuyAbeUserKeys, dummyList = bestBuyAuthority.createABEUserKeys(userEntityID=userEntityID, attributes=attributesBestBuy,
                                                                expirationEpoch=expirationEpoch, database=database)
        amazonAbeUserKeys, dummyList = amazonAuthority.createABEUserKeys(userEntityID=userEntityID, attributes=attributesAmazon,
                                                              expirationEpoch=expirationEpoch, database=database)
        locationServiceAbeUserKeys, dummyList = self.locationServiceObj.locationServiceAuthorityObject.createABEUserKeys(userEntityID=userEntityID,
                                                                                                                         attributes=attributesLocationService,
                                                                                                                         expirationEpoch=expirationEpoch,
                                                                                                                         database=database)
        # Assert any key has been created.
        self.assertEqual(len(bestBuyAbeUserKeys), len(attributesBestBuy)) # There should be 3 keys (one per attribute).
        self.assertEqual(len(amazonAbeUserKeys), len(attributesAmazon)) # There should be 2 keys (one per attribute).
        self.assertEqual(len(locationServiceAbeUserKeys), len(attributesLocationService)) # There should be 3 keys (one per attribute).
        self.assertNotEqual(bestBuyAbeUserKeys, {})
        self.assertNotEqual(amazonAbeUserKeys, {})
        self.assertNotEqual(locationServiceAbeUserKeys, {})

        # Assert that attempting to generate the keys again will result into empty dictionaries as return.
        bestBuyAbeUserKeys, dummyList = bestBuyAuthority.createABEUserKeys(userEntityID=userEntityID, attributes=attributesBestBuy,
                                                                expirationEpoch=expirationEpoch, database=database)
        amazonAbeUserKeys, dummyList = amazonAuthority.createABEUserKeys(userEntityID=userEntityID, attributes=attributesAmazon,
                                                              expirationEpoch=expirationEpoch, database=database)
        locationServiceAbeUserKeys, dummyList = self.locationServiceObj.locationServiceAuthorityObject.createABEUserKeys(userEntityID=userEntityID,
                                                                                                                         attributes=attributesLocationService,
                                                                                                                         expirationEpoch=expirationEpoch,
                                                                                                                         database=database)
        self.assertEqual(bestBuyAbeUserKeys, {})
        self.assertEqual(amazonAbeUserKeys, {})
        self.assertEqual(locationServiceAbeUserKeys, {})
        time.sleep(10) # Wait for keys to expire.

    def test_createABEUserKeysAttributesFromDatabase(self):
        """
        Here we test the creation of ABE user keys by allowing it to fetch attributes from the database.
        The attributes are those belonging to both the user and issuing authority, and valid.
        """
        userEntityID = "douggiehowser@princeton.edu"
        bestBuyID = "bestbuy.com"
        amazonID = "amazon.com"
        database = self.locationServiceDatabase # Local database to use.
        locationServiceID = constants.ENTITY_ID_LOCATION_SERVICE
        attributesBestBuy = locationserviceutility.getAllAttributesIntersectionTwoEntities(userEntityID, bestBuyID, database=database)
        attributesAmazon = locationserviceutility.getAllAttributesIntersectionTwoEntities(userEntityID, amazonID, database=database)
        attributesLocationService = locationserviceutility.getAllAttributesIntersectionTwoEntities(userEntityID, locationServiceID, database=database)
        #attributes = attributesBestBuy + attributesAmazon + attributesLocationService
        expirationEpoch = time.time() + 1 * 10 # 10 seconds.

        # Create agent objects here, since we will have more than one authority.
        # We will use the self location Service object.
        # Pay attention into specifying all databases, such that a key does not get registered to one database,
        # but the code looks for existing keys in another database.
        bestBuyAuthority = abeauthorityagent.ABEAuthority(bestBuyID, database=database)
        amazonAuthority = abeauthorityagent.ABEAuthority(amazonID, database=database)
        # Create sets of ABE user keys per authority, Location Service included. Attributes should come from the database.
        bestBuyAbeUserKeys, bestBuySerializedList = bestBuyAuthority.createABEUserKeys(userEntityID=userEntityID,
                                                                expirationEpoch=expirationEpoch, database=database)
        amazonAbeUserKeys, amazonSerializedList = amazonAuthority.createABEUserKeys(userEntityID=userEntityID,
                                                              expirationEpoch=expirationEpoch, database=database)
        locationServiceAbeUserKeys, locationServiceSerializedList = self.locationServiceObj.locationServiceAuthorityObject.createABEUserKeys(userEntityID=userEntityID,
                                                                                                                         expirationEpoch=expirationEpoch,
                                                                                                                         database=database)
        # Assert any key has been created.
        self.assertEqual(len(bestBuyAbeUserKeys), len(attributesBestBuy)) # There should be 3 keys (one per attribute).
        self.assertEqual(len(amazonAbeUserKeys), len(attributesAmazon)) # There should be 2 keys (one per attribute).
        self.assertEqual(len(locationServiceAbeUserKeys), len(attributesLocationService)) # There should be 3 keys (one per attribute).
        self.assertNotEqual(bestBuyAbeUserKeys, {})
        self.assertNotEqual(amazonAbeUserKeys, {})
        self.assertNotEqual(locationServiceAbeUserKeys, {})
        
        # Assert that both returns from the createABEUserKeys are the same. Deserialize the list of keys, compose a dict
        # and compare both dicts.
        deserializedBestBuyDict ={}
        deserializedAmazonDict = {}
        deserializedLocationServiceDict = {}
        for keys in bestBuySerializedList:
            deserializedBestBuyDict.update(json.loads(keys, cls=jsonhelper.KeyDecoder))
        for keys in amazonSerializedList:
            deserializedAmazonDict.update(json.loads(keys, cls=jsonhelper.KeyDecoder))
        for keys in locationServiceSerializedList:
            deserializedLocationServiceDict.update(json.loads(keys, cls=jsonhelper.KeyDecoder))
        self.assertEqual(bestBuyAbeUserKeys, deserializedBestBuyDict)
        self.assertEqual(amazonAbeUserKeys, deserializedAmazonDict)
        self.assertEqual(locationServiceAbeUserKeys, deserializedLocationServiceDict)
        # Assert that attempting to generate the keys again will result into empty dictionaries as return.
        bestBuyAbeUserKeys, dummyList = bestBuyAuthority.createABEUserKeys(userEntityID=userEntityID,
                                                                expirationEpoch=expirationEpoch, database=database)
        amazonAbeUserKeys, dummyList = amazonAuthority.createABEUserKeys(userEntityID=userEntityID,
                                                              expirationEpoch=expirationEpoch, database=database)
        locationServiceAbeUserKeys, dummyList = self.locationServiceObj.locationServiceAuthorityObject.createABEUserKeys(userEntityID=userEntityID,
                                                                                                              expirationEpoch=expirationEpoch,
                                                                                                              database=database)
        self.assertEqual(bestBuyAbeUserKeys, {})
        self.assertEqual(amazonAbeUserKeys, {})
        self.assertEqual(locationServiceAbeUserKeys, {})
        time.sleep(10) # Wait for keys to expire.

    def test_expireABEUserAttributeKeys(self):
        """
        The procedure to expire (and also prorogue) an ABE user key must take into account the specific attribute or attributes one
        wishes to expire/prorogue. We arrange, in this proof-of-concept, the ABE user keys to be one attribute key per database row.
        This is different than the arrangement for ABE authority keys, which we allow to be bundled together (i.e., all attribute keys)
        in a row. Typically, one row for the ABE (authority) public keys, one row for the ABE secret keys. We assume the authority
        will manipulate its keys all together, and not by attribute. There is one random component that integrates all attribute keys
        from an authority, and as such, unless we save this random component, all the authority keys must be generated at the same time.
        (Of course, we can regenerate the ABE public keys anytime from the secret keys.)

        By keeping the ABE user keys separated by attribute, we can prorogue/expire them individually, or generate new ones
        as needed (given that the authority keys did not change).

        To expire/prorogue, we obtain all rows with valid ABE user keys from a specific user. We then must select, from these
        rows, the ones with the attributes we want to manipulate. We assume an authority can only manipulate keys issued by her,
        i.e., attributes owned by the authority. This is, however, not controlled by the cryptosystem, but by the software
        engineering. In real conditions, one authority does not really have other authority's issued keys. The Location Service
        would have such power, and that is supposedly ok. Unless the user application is exploited and thus the user database could be
        hacked such that ABE keys could be expired/prorogued at will.

        There could be two ways to have the cryptosystem participate into this. One is the "vanishing attribute" or "evanescent"
        or "ephemeral attribute", which is an attribute issued by the Location Service, together with an ABE user key for all
        users, that is utilized only during a certain period of time and it is used to encrypt the BNONCE. It is a mandatory
        attribute to have to decrypt the BNONCE. Since it is ephemeral, it will be substituted after a time and users without
        it will not be able to authenticate.

        Another way is for an authority to request, as part of the multifactor authentication, a proof of knowledge utilizing
        an encrypted token using all current attributes possessed by a specific user, once the authority knows the user. As such,
        an authority would make an encrypted token to the Location Service, once the user is known. The user should decrypt this token
        and utilize its value into some operation to prove knowledge of the ABE secret keys.
        """
        userEntityID = "douggiehowser@princeton.edu"
        bestBuyID = "bestbuy.com"
        amazonID = "amazon.com"
        bestBuyAuthority = abeauthorityagent.ABEAuthority(bestBuyID, database=self.locationServiceDatabase)
        amazonAuthority = abeauthorityagent.ABEAuthority(amazonID, database=self.locationServiceDatabase)
        keyType = constants.ABE_USER_SECRET_KEY_TYPE
        keyTypeFk = locationserviceutility.getKeyTypePk(keyType, database=self.locationServiceDatabase)
        creationEpoch = time.time()
        expirationEpoch = creationEpoch + 100 # 10 seconds expiration.
        lastUsedEpoch = creationEpoch
        attributesBestBuy = ["bestbuy.com.spendinglimit.level1", "bestbuy.com.vip.gold", "bestbuy.com.vip.platinum"]
        attributesAmazon = ["amazon.com.spendinglimit.level2", "amazon.com.vip.prime"]
        attributesLocationService = ["global.payment.visa", "global.payment.androidpay", "global.store.amazon.com"]

        # Manually insert entityKey tuples here to ensure the tests will perform as expected.
        testTuples = [(userEntityID, '{"BESTBUY.COM.SPENDINGLIMIT.LEVEL1": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:pFlZCy/1369E8MlMi05FxN6FCBbDLCfSEnFgZLYWurmj9SFpFHkSPEe18/7QhlQBY9xpbNM70tDGOMg9gjYjrQA="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
                      (userEntityID, '{"BESTBUY.COM.VIP.GOLD": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:ZxI0nTd9hiXPT0O5iVvUn4Khc3GtF75j09V0drLZoPg6dCl3/fo+CPXpZFbO6aMMxeGH3pxjiiJ67ezsNAFPKQE="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
                      (userEntityID, '{"BESTBUY.COM.VIP.PLATINUM": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:LF7TXVTm76//vNg3JwiZjhmGwnG1xKHzKvvGV4chskAchTsQnJXXHMCdtM2qkr68x52bzU/9t4Ob9Qh/kC1LeAE="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
                      (userEntityID, '{"AMAZON.COM.SPENDINGLIMIT.LEVEL2": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:kLld+tXgkA5RU5b0sZ/zWaTrltMU+XnvBeCRnHs6jcD0GTe4TwcQdUcVmCkmAmcBa2d8xpyJRGL/K+P7SKCc0wE="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
                      (userEntityID, '{"AMAZON.COM.VIP.PRIME": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:Q/JfE5qe/p8yN+lgQcQbpbRgx0RhGZ/jOij3WaEO0okQDhmChxNn4EIYijHgPmpJLWx7XCShM9rE4KnDUDhWcQA="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
                      (userEntityID, '{"GLOBAL.PAYMENT.VISA": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:IUOU50I8IEWyLtSnIgYH5trxp2P5Q90l3igAnkZ12cRJCxjwo+LkWrjTeJ/0Arqzv/U0WQe6edAEZwnHDGyZgwA="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
                      (userEntityID, '{"GLOBAL.PAYMENT.ANDROIDPAY": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:jxxikKa1It+ERYeJVnLD+0l5k7JacvMPf0Us02mHSboZBLuoZdHJWvKTJ/kZjBcJdrk7mYJzupAd8a3MNC8migE="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
                      (userEntityID, '{"GLOBAL.STORE.AMAZON.COM": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:QpRhE8XJ+ErrX5QBjTze3a3BqKbPGDCiwFRyV2I/VSLSameTQPj9t1rL2Y7Mjs5zo/2dtef3x8lbzSrh4WX/jwA="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch)]

        con = sqlite3.connect(self.locationServiceDatabase)
        # Insert the rows with known values.
        with con:
            con.executemany("""insert into entityKey (entityFk, "key", salt, keyTypeFk, algorithm, creationEpoch, expirationEpoch, lastUsedEpoch) values((select primaryKey from entity where entityID=?),?,?,?,?,?,?,?)""", testTuples)

        # Done. Now let's expire the ABE user keys with 2 attributes from location.service.
        expiredRows = self.locationServiceObj.locationServiceAuthorityObject.expireABEUserAttributeKeys(userEntityID, attributes=["global.payment.visa", "global.payment.androidpay"])
        self.assertEqual(expiredRows, 2)
        # Try to expire them again, the returned number of updated rows should be zero.
        expiredRows = self.locationServiceObj.locationServiceAuthorityObject.expireABEUserAttributeKeys(userEntityID, attributes=["global.payment.visa", "global.payment.androidpay"])
        self.assertEqual(expiredRows, 0)
        # Now expire all (again) from location.service, one from amazon.com. Only the remaining 2 from location.service should be expired.
        # Since the authority is location.service, it will not expire attributes keys not issued by her.
        attributesToExpire = attributesLocationService + ["GLOBAL.STORE.AMAZON.COM"]
        expiredRows = self.locationServiceObj.locationServiceAuthorityObject.expireABEUserAttributeKeys(userEntityID, attributes=attributesToExpire)
        self.assertEqual(expiredRows, 1)
        # Obtain the valid keys. Assert that the expired ones are not there.
        existingKeys = locationserviceutility.getEntityKeysOfType(userEntityID, constants.ABE_USER_SECRET_KEY_TYPE, database=self.locationServiceDatabase)
        # Now expire the other authority keys without specifying attributes. All (from that authority) should be expired.
        self.assertEqual(len(existingKeys), len(attributesAmazon) + len(attributesBestBuy))
        expiredRows = bestBuyAuthority.expireABEUserAttributeKeys(userEntityID)
        self.assertEqual(expiredRows, 3)
        expiredRows = amazonAuthority.expireABEUserAttributeKeys(userEntityID)
        self.assertEqual(expiredRows, 2)
        # Try again to assert the keys are expired.
        expiredRows = bestBuyAuthority.expireABEUserAttributeKeys(userEntityID)
        self.assertEqual(expiredRows, 0)
        expiredRows = amazonAuthority.expireABEUserAttributeKeys(userEntityID)
        self.assertEqual(expiredRows, 0)
        
    def test_prorogueABEUserAttributeKeys(self):
        userEntityID = "douggiehowser@princeton.edu"
        bestBuyID = "bestbuy.com"
        amazonID = "amazon.com"
        database = self.locationServiceDatabase
        bestBuyAuthority = abeauthorityagent.ABEAuthority(bestBuyID, database=self.locationServiceDatabase)
        amazonAuthority = abeauthorityagent.ABEAuthority(amazonID, database=self.locationServiceDatabase)
        keyType = constants.ABE_USER_SECRET_KEY_TYPE
        keyTypeFk = locationserviceutility.getKeyTypePk(keyType, database=self.locationServiceDatabase)
        creationEpoch = time.time()
        newExpirationEpoch = creationEpoch + 10 # Ten seconds more than now.
        longerExpirationEpoch = newExpirationEpoch + 20 # Longer than newExpirationEpoch.
        lastUsedEpoch = creationEpoch
        # Save the attributes registered for this user for all authorities here.
        attributesBestBuy = locationserviceutility.getAllAttributesIntersectionTwoEntities(userEntityID, bestBuyID, database=database)
        attributesAmazon = locationserviceutility.getAllAttributesIntersectionTwoEntities(userEntityID, amazonID, database=database)
        attributesLocationService = locationserviceutility.getAllAttributesIntersectionTwoEntities(userEntityID, constants.ENTITY_ID_LOCATION_SERVICE, database=database)

        # Expire all keys from the user/authorities.
        # Therefore, when next attempting to extend existing keys, we should be unable to.
        expired = bestBuyAuthority.expireABEUserAttributeKeys(userEntityID)
        expired = amazonAuthority.expireABEUserAttributeKeys(userEntityID)
        expired = self.locationServiceObj.locationServiceAuthorityObject.expireABEUserAttributeKeys(userEntityID)

        # There should be no valid keys to extend.
        self.assertEqual(bestBuyAuthority.prorogueABEAuthorityKeys(newExpirationEpoch = newExpirationEpoch), 0)
        self.assertEqual(amazonAuthority.prorogueABEAuthorityKeys(newExpirationEpoch = newExpirationEpoch), 0)
        self.assertEqual(self.locationServiceObj.locationServiceAuthorityObject.prorogueABEAuthorityKeys(newExpirationEpoch = newExpirationEpoch), 0)
        # Now insert new keys with longerExpirationEpoch and attempt to extend them for only 10 seconds. Since the original
        # expirationEpoch is greater than the new one, there should be no modification.
        bestBuyAbeUserKeys, dummyList = bestBuyAuthority.createABEUserKeys(userEntityID=userEntityID,
                                                                expirationEpoch=longerExpirationEpoch, database=database)
        amazonAbeUserKeys, dummyList = amazonAuthority.createABEUserKeys(userEntityID=userEntityID,
                                                              expirationEpoch=longerExpirationEpoch, database=database)
        locationServiceAbeUserKeys, dummyList = self.locationServiceObj.locationServiceAuthorityObject.createABEUserKeys(userEntityID=userEntityID,
                                                                                                              expirationEpoch=longerExpirationEpoch, database=database)
        # Attempt to extend existing keys. Should not update any, since original expirationEpoch is longer than newExpirationEpoch.
        self.assertEqual(self.locationServiceObj.locationServiceAuthorityObject.prorogueABEUserAttributeKeys(userEntityID=userEntityID, newExpirationEpoch=newExpirationEpoch), 0)
        self.assertEqual(amazonAuthority.prorogueABEUserAttributeKeys(userEntityID=userEntityID, newExpirationEpoch=newExpirationEpoch), 0)
        self.assertEqual(bestBuyAuthority.prorogueABEUserAttributeKeys(userEntityID=userEntityID, newExpirationEpoch=newExpirationEpoch), 0)
        # Now ensure this new expiration occurs after the original. Attempt proroguing again, it should work.
        evenLongerExpirationEpoch = longerExpirationEpoch + 20
        self.assertEqual(self.locationServiceObj.locationServiceAuthorityObject.prorogueABEUserAttributeKeys(userEntityID=userEntityID, newExpirationEpoch=evenLongerExpirationEpoch), len(attributesLocationService))
        self.assertEqual(amazonAuthority.prorogueABEUserAttributeKeys(userEntityID=userEntityID, newExpirationEpoch=evenLongerExpirationEpoch), len(attributesAmazon))
        self.assertEqual(bestBuyAuthority.prorogueABEUserAttributeKeys(userEntityID=userEntityID, newExpirationEpoch=evenLongerExpirationEpoch), len(attributesBestBuy))
        # Clean the keys from the database by expiring.
        expired = bestBuyAuthority.expireABEUserAttributeKeys(userEntityID)
        expired = amazonAuthority.expireABEUserAttributeKeys(userEntityID)
        expired = self.locationServiceObj.locationServiceAuthorityObject.expireABEUserAttributeKeys(userEntityID)



    def test_sqliterow(self):
        conn = sqlite3.connect(":memory:")
        c = conn.cursor()
        c.execute('''create table stocks (date text, trans text, symbol text, qty real, price real)''')
        c.execute("""insert into stocks values ('2006-01-05','BUY','RHAT',100,35.14)""")
        conn.commit()
        c.close()

        """
        conn.row_factory = sqlite3.Row
        >>> c = conn.cursor()
        >>> c.execute('select * from stocks')
        <sqlite3.Cursor object at 0x7f4e7dd8fa80>
        >>> r = c.fetchone()
        >>> type(r)
        <class 'sqlite3.Row'>
        >>> tuple(r)
        ('2006-01-05', 'BUY', 'RHAT', 100.0, 35.14)
        dict(r)
        {'price': 35.14, 'qty': 100.0, 'symbol': 'RHAT', 'trans': 'BUY', 'date': '2006-01-05'}
        >>> len(r)
        5
        >>> r[2]
        'RHAT'
        >>> r.keys()
        ['date', 'trans', 'symbol', 'qty', 'price']
        >>> r['qty']
        100.0
        >>> for member in r:
        ...     print(member)
        ...
        2006-01-05
        BUY
        RHAT
        100.0
        35.14
        """

    def tearDown(self):
        pass

if __name__ == '__main__':
    unittest.main(verbosity=2)

