'''
Shashank Agrawal, Melissa Chase

| From: "FAME: Fast Attribute-based Message Encryption"
| Published in: 2017
| Available from: https://eprint.iacr.org/2017/807
| Notes: Implemented the scheme in Appendix B
| Security Assumption: a variant of k-linear, k>=2
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


class AC17KPABE(ABEnc):
    def __init__(self, group_obj, assump_size, verbose=False):
        ABEnc.__init__(self)
        self.name = "AC17 KP-ABE k=" + str(assump_size)
        self.group = group_obj
        self.assump_size = assump_size  # size of linear assumption, at least 2
        self.util = MSP(self.group, verbose)

    def setup(self):
        """
        Generates public key and master secret key.
        """

        if debug:
            print('\nSetup algorithm:\n')

        # generate two instances of the k-linear assumption
        A = []
        B = []
        for i in range(self.assump_size):
            A.append(self.group.random(ZR))
            B.append(self.group.random(ZR))  # note that A, B are vectors here

        # vector
        k = []
        for i in range(self.assump_size + 1):
            k.append(self.group.random(ZR))

        # pick a random element from the two source groups and pair them
        g = self.group.random(G1)
        h = self.group.random(G2)
        e_gh = pair(g, h)

        # now compute various parts of the public parameters

        # compute the [A]_2 term
        h_A = []
        for i in range(self.assump_size):
            h_A.append(h ** A[i])
        h_A.append(h)

        # compute the e([k]_1, [A]_2) term
        g_k = []
        for i in range(self.assump_size + 1):
            g_k.append(g ** k[i])

        e_gh_kA = []
        for i in range(self.assump_size):
            e_gh_kA.append(e_gh ** (k[i] * A[i] + k[self.assump_size]))

        # the public key
        pk = {'h_A': h_A, 'e_gh_kA': e_gh_kA}

        # the master secret key
        msk = {'g': g, 'h': h, 'g_k': g_k, 'A': A, 'B': B}

        return pk, msk

    def encrypt(self, pk, msg, attr_list):
        """
         Encrypt a message M under a set of attributes.
        """

        if debug:
            print('Encryption algorithm:\n')

        # pick randomness
        s = []
        sum = 0
        for i in range(self.assump_size):
            rand = self.group.random(ZR)
            s.append(rand)
            sum += rand

        # compute the [As]_2 term
        C_0 = []
        h_A = pk['h_A']
        for i in range(self.assump_size):
            C_0.append(h_A[i] ** s[i])
        C_0.append(h_A[self.assump_size] ** sum)

        C = {}
        for attr in attr_list:
            ct = []
            for l in range(self.assump_size+1):
                prod = 1
                for t in range(self.assump_size):
                    input_for_hash = attr + str(l) + str(t)
                    prod *= (self.group.hash(input_for_hash, G1) ** (s[t]))
                ct.append(prod)
            C[attr] = ct

        # compute the e(g, h)^(k^T As) . m term
        Cp = 1
        for i in range(self.assump_size):
            Cp = Cp * (pk['e_gh_kA'][i] ** s[i])
        Cp = Cp * msg

        return {'attr_list': attr_list, 'C_0': C_0, 'C': C, 'Cp': Cp }


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
        r = []
        sum = 0
        for i in range(self.assump_size):
            rand = self.group.random(ZR)
            r.append(rand)
            sum += rand

        Br = []
        for i in range(self.assump_size):
            Br.append(msk['B'][i] * r[i])
        Br.append(sum)

        # compute the [As]_2 term
        K_0 = []
        for br in Br:
            K_0.append(msk['h'] ** br)

        # compute the [(V^T As||U^T_2 As||...) M^T_i + W^T_i As]_1 terms

        # pre-compute hashes
        hash_table = []
        for j in range(num_cols):
            x = []
            input_for_hash1 = '0' + str(j + 1)
            for l in range(self.assump_size + 1):
                y = []
                input_for_hash2 = input_for_hash1 + str(l)
                for t in range(self.assump_size):
                    input_for_hash3 = input_for_hash2 + str(t)
                    hashed_value = self.group.hash(input_for_hash3, G1)
                    y.append(hashed_value)
                    # if debug: print ('Hash of', i+2, ',', j2, ',', j1, 'is', hashed_value)
                x.append(y)
            hash_table.append(x)

        # pick sigma'
        sigmaCol = [0]
        for i in range(num_cols-1):
            rand = self.group.random(ZR)
            sigmaCol.append(rand)

        K = {}
        for attr, row in mono_span_prog.items():
            sk = []
            attr_stripped = self.util.strip_index(attr)  # no need, re-use not allowed
            cols = len(row)
            sigma_attr = self.group.random(ZR)
            for t in range(self.assump_size):
                prod = msk['g'] ** (sigma_attr/msk['A'][t])
                prod *= (msk['g_k'][t] ** row[0])
                for l in range(self.assump_size+1):
                    input_for_hash = attr_stripped + str(l) + str(t)
                    prod1 = self.group.hash(input_for_hash, G1)
                    for j in range(2,cols):
                        # input_for_hash = '0' + str(j+1) + str(l) + str(t)
                        prod1 *= (hash_table[j][l][t] ** row[j])
                    prod *= (prod1 ** (Br[l]/msk['A'][t]))
                exp = 0
                for j in range(2,cols):
                    # compute exponent for sigma'
                    exp += (sigmaCol[j]/msk['A'][t]) * row[j]
                prod *= msk['g'] ** exp
                sk.append(prod)
            sk3 = msk['g'] ** (-sigma_attr) * msk['g_k'][self.assump_size] ** row[0]
            for j in range(2,cols):
                sk3 *= msk['g'] ** (sigmaCol[j]*row[j])
            sk.append(sk3)
            K[attr] = sk

        return {'policy': policy, 'K_0': K_0, 'K': K}

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

        prod1_GT = 1
        prod2_GT = 1
        for i in range(self.assump_size + 1):
            prod_H = 1
            prod_G = 1
            for node in nodes:
                attr = node.getAttributeAndIndex()
                attr_stripped = self.util.strip_index(attr)  # no need, re-use not allowed
                prod_H *= key['K'][attr][i]
                prod_G *= ctxt['C'][attr_stripped][i]
            prod1_GT *= pair(prod_H, ctxt['C_0'][i])
            prod2_GT *= pair(prod_G, key['K_0'][i])

        return ctxt['Cp'] * prod2_GT / prod1_GT
