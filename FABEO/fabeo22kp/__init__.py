'''
Doreen Riepel, Hoeteck Wee

| From: "FABEO: Fast Attribute-Based Encryption with Optimal Security"
| Published in: 2022
| Notes: Implemented the scheme in Figure 1 (right)
|
| type:           key-policy attribute-based encryption
| setting:        Pairing

:Authors:         Doreen Riepel
:Date:            06/2023
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from ..msp import MSP

debug = False


class FABEO22KPABE(ABEnc):
    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.name = "FABEO KP-ABE"
        self.group = group_obj
        self.util = MSP(self.group, verbose)

    def setup(self):
        """
        Generates public key and master secret key.
        """

        if debug:
            print('\nSetup algorithm:\n')

        # pick a random element from the two source groups and pair them
        g1 = self.group.random(G1)
        g2 = self.group.random(G2)
        e_g1g2 = pair(g1, g2)
        
        alpha = self.group.random(ZR)

        # now compute various parts of the public parameters
        e_g1g2_alpha = e_g1g2 ** alpha

        # the master secret and public key
        msk = {'alpha': alpha}
        pk = {'g1': g1, 'g2': g2, 'e_g1g2_alpha': e_g1g2_alpha}

        return pk, msk

    def encrypt(self, pk, msg, attr_list):
        """
        Encrypt a message msg under a policy string.
        """

        if debug:
            print('\nEncryption algorithm:\n')

        s = self.group.random(ZR)
        g2_s = pk['g2'] ** s

        ct = {}
        for attr in attr_list:
            attrHash = self.group.hash(attr, G1)
            ct[attr] = attrHash ** s
                    
        # compute the e(g, h)^(As) * m term
        Cp = pk['e_g1g2_alpha'] ** s
        Cp = Cp * msg

        return {'attr_list': attr_list, 'g2_s': g2_s, 'ct': ct, 'Cp': Cp}

    def keygen(self, pk, msk, policy_str):
        """
        Generate a key for a list of attributes.
        """

        if debug:
            print('\nKey generation algorithm:\n')

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # pick randomness
        r = self.group.random(ZR)

        g2_r = pk['g2'] ** r
        
        # pick random shares
        v = [msk['alpha']]
        for i in range(num_cols-1):
            rand = self.group.random(ZR)
            v.append(rand)

        sk = {}
        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)
            attrHash = self.group.hash(attr_stripped, G1)
            len_row = len(row)
            Mivtop = sum(i[0] * i[1] for i in zip(row, v[:len_row]))
            sk[attr] = pk['g1'] ** Mivtop * attrHash ** r

        return {'policy': policy, 'g2_r': g2_r, 'sk': sk}

    def decrypt(self, pk, ctxt, key):
        """
        Decrypt ciphertext ctxt with key key.
        """

        if debug:
            print('\nDecryption algorithm:\n')

        nodes = self.util.prune(key['policy'], ctxt['attr_list'])

        if not nodes:
            print ("Policy not satisfied.")
            return None

        prod_sk = 1
        prod_ct = 1
        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)  # no need, re-use not allowed

            prod_sk *= key['sk'][attr]
            prod_ct *= ctxt['ct'][attr_stripped]
        
        e1 = pair(prod_sk, ctxt['g2_s'])
        e2 = pair(prod_ct, key['g2_r'])

        kem = e1/e2

        return ctxt['Cp'] / kem