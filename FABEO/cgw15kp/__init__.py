'''
Jie Chen, Romain Gay, and Hoeteck Wee

| From: "Improved Dual System ABE in Prime-Order Groups via Predicate Encodings"
| Published in: 2015
| Available from: http://eprint.iacr.org/2015/409
| Notes: Implemented the scheme in Appendix B.1
| Security Assumption: k-linear
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


class CGW15KPABE(ABEnc):
    def __init__(self, groupObj, assump_size, uni_size, verbose=False):
        ABEnc.__init__(self)
        self.name = "CGW15 KP-ABE k=" + str(assump_size)
        self.group = groupObj
        self.assump_size = assump_size  # size of the linear assumption
        self.uni_size = uni_size  # bound on the size of the universe of attributes
        self.util = MSP(self.group, verbose)

    def setup(self):
        """
        Generates public key and master secret key.
        """

        if debug:
            print('Setup algorithm:\n')

        # generate two instances of the k-linear assumption
        A = []
        B = []
        for i in range(self.assump_size):
            A.append(self.group.random(ZR))
            B.append(self.group.random(ZR))  # note that A, B are vectors here

        # pick matrices that help to randomize basis
        W = {}
        for i in range(self.uni_size):
            x = []
            for j1 in range(self.assump_size + 1):
                y = []
                for j2 in range(self.assump_size + 1):
                    y.append(self.group.random(ZR))
                x.append(y)
            W[i + 1] = x
        
        U = {}
        for i in range(self.uni_size):
            x = []
            for j1 in range(self.assump_size + 1):
                y = []
                for j2 in range(self.assump_size + 1):
                    y.append(self.group.random(ZR))
                x.append(y)
            U[i + 1] = x

        # vector
        k = []
        for i in range(self.assump_size + 1):
            k.append(self.group.random(ZR))

        # pick a random element from the two source groups and pair them
        g = self.group.random(G1)
        h = self.group.random(G2)
        e_gh = pair(g, h)

        # now compute various parts of the public parameters

        # compute the [A]_1 term
        g_A = []
        for i in range(self.assump_size):
            g_A.append(g ** A[i])
        g_A.append(g)

        # compute the [W_1^T A]_1, [W_2^T A]_1, ...  terms
        g_WA = {}
        for i in range(self.uni_size):
            x = []
            for j1 in range(self.assump_size + 1):
                y = []
                for j2 in range(self.assump_size):
                    prod = (A[j2] * W[i + 1][j2][j1]) + W[i + 1][self.assump_size][j1]
                    y.append(g ** prod)
                x.append(y)
            g_WA[i + 1] = x

        # compute the e([A]_1, [k]_2) term
        h_k = []
        for i in range(self.assump_size + 1):
            h_k.append(h ** k[i])

        e_gh_kA = []
        for i in range(self.assump_size):
            e_gh_kA.append(e_gh ** (k[i] * A[i] + k[self.assump_size]))

        # the public key
        pk = {'g_A': g_A, 'g_WA': g_WA, 'e_gh_kA': e_gh_kA}

        # the master secret key
        msk = {'h': h, 'k': k, 'B': B, 'W': W, 'U': U}

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
        s.append(sum)

        # compute the [As]_1 term
        C_0 = []
        g_A = pk['g_A']
        for i in range(self.assump_size + 1):
            C_0.append(g_A[i] ** s[i])


        # compute the [W_i^T Br]_2 terms
        C = {}
        for attr in attr_list:
            ct = []
            W_attr = pk['g_WA'][int(attr)]
            for j1 in range(self.assump_size + 1):
                prod = 1
                for j2 in range(self.assump_size):
                    prod *= W_attr[j1][j2] ** s[j2]
                ct.append(prod)
            C[attr] = ct

        # compute the e(g, h)^(k^T As) . m term
        Cx = 1
        for i in range(self.assump_size):
            Cx = Cx * (pk['e_gh_kA'][i] ** s[i])
        Cx = Cx * msg

        return {'attr_list': attr_list, 'C_0': C_0, 'C': C, 'Cx': Cx}

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
        r = []
        sum = 0
        for i in range(self.assump_size):
            rand = self.group.random(ZR)
            r.append(rand)
            sum += rand
        
        # compute the [Br]_2 term
        K_0 = []
        Br = []
        h = msk['h']
        for i in range(self.assump_size):
            prod = msk['B'][i] * r[i]
            Br.append(prod)
            K_0.append(h ** prod)
        Br.append(sum)
        K_0.append(h ** sum)

        # compute the U_2 Br, ..., U_col Br terms
        UBr = {}
        for i in range(1,num_cols):
            x = []
            for j1 in range(self.assump_size + 1):
                sum = 0
                for j2 in range(self.assump_size + 1):
                    sum += Br[j2] * msk['U'][i][j1][j2]
                x.append(sum)
            UBr[i] = x

        # compute the [(k||U_2 Br||...||U_cols Br) M^T_i + W_i Br]_1 terms
        K = {}
        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)  # no need, re-use not allowed
            num_cols = len(row)
            key = []
            for j1 in range(self.assump_size + 1):
                sum1 = msk['k'][j1] * row[0]
                for i in range(1,num_cols):
                    sum1 += UBr[i][j1] * row[i]
                for j2 in range(self.assump_size + 1):
                    sum1 += msk['W'][int(attr_stripped)][j1][j2] * Br[j2]
                key.append(h ** sum1)
            K[attr] = key

        return {'policy': policy, 'K_0': K_0, 'K': K}

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
            prod1_GT *= pair(ctxt['C_0'][i], prod_H)
            prod2_GT *= pair(prod_G, key['K_0'][i])

        return ctxt['Cx'] * prod2_GT / prod1_GT
