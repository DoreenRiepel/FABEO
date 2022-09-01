'''
Doreen Riepel, Hoeteck Wee

| From: "FABEO: Fast Attribute-Based Encryption with Optimal Security"
| Published in: 2022
| Notes: Implemented the scheme in Section 8.2
|
| type:           functional encryption ("public index")
| setting:        Pairing

:Authors:         Doreen Riepel
:Date:            08/2022
'''

from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.DFA import DFA

debug = False

class FABEO22DFA:
    def __init__(self, groupObj, dfaObj):
        # global group, dfaObj
        self.name = "FABEO DFA"
        self.group = groupObj
        self.dfaObj = dfaObj
        
    def setup(self, alphabet):
        
        # pick a random element from the two source groups and pair them
        g = self.group.random(G1)
        h = self.group.random(G2)
        e_gh = pair(g, h)

        w_start, w_end, z = self.group.random(ZR,3)

        w = {'start':w_start, 'end':w_end }
        for sigma in alphabet:
            w[str(sigma)] = self.group.random(ZR)
        
        g_w = {}
        for label, w_i in w.items():
            g_w[label] = g ** w_i
        g_z = g ** z
        
        alpha = self.group.random(ZR)
        
        msk = {'h': h, 'z': z, 'w':w, 'alpha': alpha}
        mpk = {'g': g, 'g_z':g_z, 'g_w':g_w, 'e_gh_alpha':e_gh ** alpha }
        return (mpk, msk)

    def keygen(self, mpk, msk, dfaM):
        Q, S, T, q0, F = dfaM
        q = len(Q)
        # associate D_i with each state q_i in Q

        d = {}
        r = {}
        h_r = {}

        for u in Q:
            d_u = self.group.random(ZR)
            d[str(u)] = d_u
            r_u = self.group.random(ZR)
            r[str(u)] = r_u
            h_r[str(u)] = msk['h'] ** r_u

        K = {}
        K['start1'] = msk['h'] ** (d[str(Q[0])] + msk['w']['start'] * r[str(Q[0])])
        K['start2'] = msk['h'] ** r[str(Q[0])]

        
        for t in T: # for each tuple, t in transition list
            (x, y, sigma) = t
            K[str(t)] = {}
            K[str(t)][1] = msk['h'] ** (-d[str(x)] + msk['z'] * r[str(x)])
           # K[str(t)][2] = msk['h'] ** r[str(x)]
            K[str(t)][3] = msk['h'] ** (d[str(y)] + msk['w'][str(sigma)] * r[str(x)])

        # for each accept state in the set of all accept states
        K['end'] = {}
        for x in F:
            K['end'][str(x)] = {}
            K['end'][str(x)][1] = msk['h'] ** (msk['alpha'] - d[str(x)] + msk['w']['end'] * r[str(x)])
           # K['end'][str(x)][2] = msk['h'] ** r[str(x)]
            
        sk = {'K':K, 'h_r':h_r, 'dfaM':dfaM }
        return sk

    def encrypt(self, mpk, x, M):
        l = len(x) # symbols of string        
        s = self.group.random(ZR, l+1) # l+1 b/c it includes 'l'-th index
        C = {}
        C['m'] = M * (mpk['e_gh_alpha'] ** s[l])
        
        C[0] = {}
        C[0][1] = mpk['g'] ** s[0]
        C[0][2] = mpk['g_w']['start'] ** s[0]
        
        for i in range(1, l+1):
            C[i] = {}
            C[i][1] = mpk['g'] ** s[i]
            C[i][2] = (mpk['g_z'] ** s[i-1]) * (mpk['g_w'][str(x[i])] ** s[i])
        
        C['end'] = mpk['g_w']['end'] ** s[l]      
        ct = {'C':C, 'x':x}
        return ct

    def decrypt(self, sk, ct):
        K, h_r, dfaM = sk['K'], sk['h_r'], sk['dfaM']
        C, x = ct['C'], ct['x']
        l = len(x)
        B = {}
        # if DFA does not accept string, return immediately
        if not self.dfaObj.accept(dfaM, x):
            print("DFA rejects: ", x)
            return False
        
        Ti = self.dfaObj.getTransitions(dfaM, x) # returns a tuple of transitions 
        B[0] = pair(C[0][1],  K['start1']) / pair(C[0][2], K['start2'])

        for i in range(1, l+1):
            ti = Ti[i]
            if debug: print("transition: ", ti)
            B[i] = B[i-1] * ( pair(C[i-1][1], K[str(ti)][1]) / pair(C[i][2], h_r[str(ti[0])]) ) * pair(C[i][1], K[str(ti)][3])

        x = self.dfaObj.getAcceptState(Ti) # retrieve accept state
        Bend = B[l] * pair(C[l][1], K['end'][str(x)][1]) / pair(C['end'], h_r[str(x)])
        M = C['m'] / Bend  
        return M