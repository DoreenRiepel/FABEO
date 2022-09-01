'''
Miguel Ambrona, Gilles Barthe, Romain Gay, and Hoeteck Wee

| From: "Attribute-Based Encryption in the Generic Group Model: Automated Proofs and New Constructions
| Published in: 2017
| Available from: https://dl.acm.org/doi/pdf/10.1145/3133956.3134088
| Notes: Implemented the unbounded KP-ABE scheme in Section 5.3
|
| type:           key-policy attribute-based encryption
| setting:        Pairing

:Authors:          Doreen Riepel
:Date:            4/2022
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from ..msp import MSP

debug = False


class ABGW17KPABE(ABEnc):
    def __init__(self, groupObj, verbose=False):
        ABEnc.__init__(self)
        self.name = "ABGW17 KP-ABE"
        self.group = groupObj
        self.util = MSP(self.group, verbose)

    def setup(self):
        """
        Generates public key and master secret key.
        """

        if debug:
            print('Setup algorithm:\n')

        # pick a random element from the two source groups and pair them
        g = self.group.random(G1)
        h = self.group.random(G2)
        e_gh = pair(g, h)

        # pick vector B
        b1 = self.group.random(ZR)
        b2 = self.group.random(ZR)

        B1 = g ** b1
        B2 = g ** b2

        alpha = self.group.random(ZR)
        e_gh_A = e_gh ** alpha
        
        # the public key
        pk = {'g': g, 'B1': B1, 'B2': B2, 'e_gh_A': e_gh_A}

        # the master secret key
        msk = {'h': h, 'b1': b1, 'b2': b2, 'alpha': alpha}

        return pk, msk

    def keygen(self, pk, msk, policy_str):
        """
        Generate a key for a policy string.
        """

        if debug:
            print('Key generation algorithm:\n')

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # pick randomness
        R = [msk['alpha']]
        for i in range(num_cols-1):
            rand = self.group.random(ZR)
            R.append(rand)
        
        K_0 = {}
        K_1 = {}
        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)  # no need, re-use not allowed
            cols = len(row)

            # compute the [M^T_j (a,r)]_2 term
            exp = sum(i[0] * i[1] for i in zip(row, R[:cols]))
            K_0[attr] = msk['h'] ** exp

            # compute the [M^T_j (a,r) / (b1+rho(j)b2)]_2 term
            exp2 = msk['b1'] + int(attr_stripped)*msk['b2']
            K_1[attr] = msk['h'] ** (exp/exp2)

        return {'policy': policy, 'K_0': K_0, 'K_1': K_1}
    
    def encrypt(self, pk, msg, attr_list):
        """
        Encrypt a message M under a set of attributes.
        """

        if debug:
            print('Encryption algorithm:\n')

        # pick randomness
        s0 = self.group.random(ZR)
        S = {}
        for attr in attr_list:
            rand = self.group.random(ZR)
            S[attr] = rand

        C_0 = {}
        C_1 = {}
        for attr in attr_list:
            # compute the [s-si]_1 terms
            C_0[attr] = pk['g'] ** (s0 - S[attr])
        
            # compute the [si(b1+ib2)]_1 terms
            C_1[attr] = (pk['B1'] * (pk['B2'] ** int(attr))) ** S[attr]

        # compute the e(g, h)^(as0) term
        Cx = pk['e_gh_A'] ** s0 * msg

        return {'attr_list': attr_list, 'C_0': C_0, 'C_1': C_1, 'Cx': Cx}

    def decrypt(self, pk, ctxt, key):
        """
        Decrypt ciphertext ctxt with key key.
        """

        if debug:
            print('Decryption algorithm:\n')

        nodes = self.util.prune(key['policy'], ctxt['attr_list'])
        if not nodes:
            print ("Policy not satisfied.")
            return None

        prod1 = 1
        prod2 = 1

        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)  # no need, re-use not allowed
            prod1 *= pair(ctxt['C_0'][attr_stripped], key['K_0'][attr])
            prod2 *= pair(ctxt['C_1'][attr_stripped], key['K_1'][attr])

        return ctxt['Cx'] / (prod1 * prod2)
