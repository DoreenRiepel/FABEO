'''
Miguel Ambrona, Gilles Barthe, Romain Gay, and Hoeteck Wee

| From: "Attribute-Based Encryption in the Generic Group Model: Automated Proofs and New Constructions
| Published in: 2017
| Available from: https://dl.acm.org/doi/pdf/10.1145/3133956.3134088
| Notes: Implemented the unbounded CP-ABE scheme in Section 5.3
|
| type:           ciphertext-policy attribute-based encryption
| setting:        Pairing

:Authors:          Doreen Riepel
:Date:            4/2022
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from ..msp import MSP

debug = False

class ABGW17CPABE(ABEnc):
    def __init__(self, groupObj, verbose=False):
        ABEnc.__init__(self)
        self.name = "ABGW17 CP-ABE"
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
        v = self.group.random(ZR)
        w = self.group.random(ZR)

        B1 = g ** b1
        B2 = g ** b2
        V = g ** v
        W = g ** w

        alpha = self.group.random(ZR)
        e_gh_A = e_gh ** alpha
        
        # the public key
        pk = {'g': g, 'B1': B1, 'B2': B2, 'V': V, 'W': W, 'e_gh_A': e_gh_A}

        # the master secret key
        msk = {'h': h, 'b1': b1, 'b2': b2, 'v': v, 'w': w, 'alpha': alpha}

        return pk, msk

    def keygen(self, pk, msk, attr_list):
        """
        Generate a key for a set of attributes.
        """

        if debug:
            print('Key generation algorithm:\n')

        # pick randomness
        r = self.group.random(ZR)

        # compute the [r]_2, [a-wr]_2 terms
        K_0 = msk['h'] ** r
        K_1 = msk['h'] ** (msk['alpha'] - msk['w']*r)

        K = {}
        # compute the [rv / (b1+yb2)]_2 term
        for attr in attr_list:
            K[attr] = msk['h'] ** (r*msk['v'] / (msk['b1'] + int(attr)* msk['b2']))
        
        return {'attr_list': attr_list, 'K_0': K_0, 'K_1': K_1, 'K': K }

    def encrypt(self, pk, msg, policy_str):
        """
        Encrypt a message M under a policy string.
        """

        if debug:
            print('Encryption algorithm:\n')

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # pick randomness
        s0 = self.group.random(ZR)
        U = [s0]
        for i in range(num_cols-1):
            rand = self.group.random(ZR)
            U.append(rand)
        
        C_0 = {}
        C_1 = {}
        C_2 = {}
        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)  # no need, re-use not allowed
            cols = len(row)

            # compute the [si(b1+xb2)]_1 term
            si = self.group.random(ZR)
            C_0[attr] = (pk['B1'] * (pk['B2'] ** int(attr_stripped))) ** si

            # compute the [M^T_i (s,u)]_1 term
            MuT = sum(i[0] * i[1] for i in zip(row, U[:cols]))
            C_1[attr] = pk['g'] ** MuT

            # compute the [-vsi + w M^T_i (s,u)]_1 term
            C_2[attr] = pk['V']**(-si) * pk['W'] ** MuT

        # compute the e(g,h)^(as0) term
        Cx = pk['e_gh_A'] ** s0 * msg

        return {'policy': policy, 'C_0': C_0, 'C_1': C_1, 'C_2': C_2, 'Cx': Cx}

    def decrypt(self, pk, ctxt, key):
        """
        Decrypt ciphertext ctxt with key key.
        """

        if debug:
            print('Decryption algorithm:\n')

        nodes = self.util.prune(ctxt['policy'], key['attr_list'])
        if not nodes:
            print ("Policy not satisfied.")
            return None

        prod1 = 1
        prodC1 = 1
        prodC2 = 1

        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)  # no need, re-use not allowed
            prod1 *= pair(ctxt['C_0'][attr], key['K'][attr_stripped])
            prodC1 *= ctxt['C_1'][attr]
            prodC2 *= ctxt['C_2'][attr]

        kem = prod1 * pair(prodC1, key['K_1']) * pair(prodC2, key['K_0'])

        return ctxt['Cx'] / kem
