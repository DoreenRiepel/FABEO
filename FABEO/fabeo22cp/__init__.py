'''
Doreen Riepel, Hoeteck Wee

| From: "FABEO: Fast Attribute-Based Encryption with Optimal Security"
| Published in: 2022
| Notes: Implemented the scheme in Figure 1 (left)
|
| type:           ciphertext-policy attribute-based encryption
| setting:        Pairing

:Authors:         Doreen Riepel
:Date:            06/2023
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from ..msp import MSP

debug = False

class FABEO22CPABE(ABEnc):
    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.name = "FABEO CP-ABE"
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

    def keygen(self, pk, msk, attr_list):
        """
        Generate a key for a list of attributes.
        """

        if debug:
            print('\nKey generation algorithm:\n')

        r = self.group.random(ZR)
        g2_r = pk['g2'] ** r

        sk1 = {}
        for attr in attr_list:
            attrHash = self.group.hash(attr, G1)
            sk1[attr] = attrHash ** r
        
        bHash = self.group.hash(str(self.group.order()+1), G1) # ZR+1
        
        sk2 = pk['g1'] ** msk['alpha'] * bHash ** r

        return {'attr_list': attr_list, 'g2_r': g2_r, 'sk1': sk1, 'sk2': sk2}

    def encrypt(self, pk, msg, policy_str):
        """
        Encrypt a message msg under a policy string.
        """

        if debug:
            print('\nEncryption algorithm:\n')

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # pick randomness
        s1 = self.group.random(ZR)
        sprime = self.group.random(ZR)

        g2_s1 = pk['g2'] ** s1
        g2_sprime = pk['g2'] ** sprime
        
        # pick random shares
        v = [s1]
        for i in range(num_cols-1):
            rand = self.group.random(ZR)
            v.append(rand)
        
        bHash = self.group.hash(str(self.group.order()+1), G1) # ZR+1

        ct = {}
        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)
            attrHash = self.group.hash(attr_stripped, G1)
            len_row = len(row)
            Mivtop = sum(i[0] * i[1] for i in zip(row, v[:len_row]))
            ct[attr] = bHash ** Mivtop * attrHash ** sprime
            
        # compute the e(g, h)^(As) * m term
        Cp = pk['e_g1g2_alpha'] ** s1
        Cp = Cp * msg

        return {'policy': policy, 'g2_s1': g2_s1, 'g2_sprime': g2_sprime, 'ct': ct, 'Cp': Cp}

    def decrypt(self, pk, ctxt, key):
        """
        Decrypt ciphertext ctxt with key key.
        """

        if debug:
            print('\nDecryption algorithm:\n')

        nodes = self.util.prune(ctxt['policy'], key['attr_list'])
        # print(nodes)
        if not nodes:
            print ("Policy not satisfied.")
            return None

        prod_sk = 1
        prod_ct = 1
        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)  # no need, re-use not allowed

            prod_sk *= key['sk1'][attr_stripped]
            prod_ct *= ctxt['ct'][attr]
        
        e0 = pair(key['sk2'], ctxt['g2_s1'])
        e1 = pair(prod_sk, ctxt['g2_sprime'])
        e2 = pair(prod_ct, key['g2_r'])

        kem = e0 * (e1/e2)

        return ctxt['Cp'] / kem