'''
:Date:            4/2022
'''

from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.toolbox.DFA import DFA
from FABEO.fabeo22dfa import FABEO22DFA
from FABEO.waters12dfa import WATERS12DFA

def run_dfa(fe, alphabet, dfaM, x, msg):
    
    (mpk, msk) = fe.setup(alphabet)
    sk = fe.keygen(mpk, msk, dfaM)
    ct = fe.encrypt(mpk, x, msg)
    rec_msg = fe.decrypt(sk, ct)

    if debug:
        if rec_msg == msg:
            print("Successful decryption for {}.".format(fe.name))
        else:
            print("Decryption failed for {}.".format(fe.name))

def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT224')
    
    alphabet = {'a', 'b'}

    regex = "ab*a"
    x_string = "abba"

    dfa = DFA(regex, alphabet)
    dfaM = dfa.constructDFA()
    x = dfa.getSymbols(x_string)

    # choose a random message
    msg = pairing_group.random(GT)

    waters = WATERS12DFA(pairing_group, dfa)
    run_dfa(waters, alphabet, dfaM, x, msg)

    fabeo = FABEO22DFA(pairing_group, dfa)
    run_dfa(fabeo, alphabet, dfaM, x, msg)

if __name__ == "__main__":
    debug = True
    main()
