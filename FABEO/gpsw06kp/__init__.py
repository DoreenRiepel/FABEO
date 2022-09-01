'''
Vipul Goyal, Omkant Pandey, Amit Sahai, Brent Waters

| From: "Attribute-Based Encryption for Fine-Grained Access Control of Encrypted Data"
| Published in: 2006
| Available from: https://eprint.iacr.org/2006/309.pdf
| Notes: Implemented the scheme in Appendix A.1
|
| type:           key-policy attribute-based encryption
| setting:        Pairing

:Authors:         Doreen Riepel
:Date:            04/2022
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from ..msp import MSP

debug = False


class GPSW06KPABE(ABEnc):

    def __init__(self, group_obj, uni_size, verbose=False):
        ABEnc.__init__(self)
        self.name = "GPSW06 KP-ABE"
        self.group = group_obj
        self.uni_size = uni_size  # bound on the size of the universe of attributes
        self.util = MSP(self.group, verbose)

    def setup(self):
        """
        Generates public key and master secret key.
        """

        if debug:
            print('Setup algorithm:\n')

        # pick a random element each from two source groups and pair them
        g1 = self.group.random(G1)
        g2 = self.group.random(G2)
        alpha = self.group.random(ZR)
        e_gg_alpha = pair(g1, g2) ** alpha

        g_t = [1]
        t = [0]
        for i in range(self.uni_size):
            ti = self.group.random(ZR)
            t.append(ti)
            g_ti = g1 ** ti
            g_t.append(g_ti)

        pk = {'g_t': g_t, 'e_gg_alpha': e_gg_alpha}
        msk = {'g2': g2, 't': t, 'alpha': alpha}
        return pk, msk

    def encrypt(self, pk, msg, attr_list):
        """
         Encrypt a message M under a set of attributes.
        """

        if debug:
            print('Encryption algorithm:\n')

        s = self.group.random(ZR)
        c0 = pk['e_gg_alpha'] ** s * msg


        cy = {}
        for attr in attr_list:
            cy[attr] = pk['g_t'][int(attr)] ** s

        return {'attr_list': attr_list, 'c0': c0, 'cy': cy}

    def keygen(self, pk, msk, policy_str):
        """
        Generate a key for a monotone span program.
        """

        if debug:
            print('Key generation algorithm:\n')

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # pick randomness
        u = [msk['alpha']]
        for i in range(num_cols-1):
            rand = self.group.random(ZR)
            u.append(rand)

        k = {}
        for attr, row in mono_span_prog.items():
            cols = len(row)
            sum = 0
            for i in range(cols):
                sum += row[i] * u[i]
            attr_stripped = self.util.strip_index(attr)
            di = msk['g2'] ** (sum/msk['t'][int(attr_stripped)])
            k[attr] = di

        return {'policy': policy, 'k': k}

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

        prodGT = 1

        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)
            prodGT *= pair(ctxt['cy'][attr_stripped],key['k'][attr])

        return (ctxt['c0'] / prodGT)
