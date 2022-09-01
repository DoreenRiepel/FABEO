'''
:Date:            4/2022
'''

from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.toolbox.DFA import DFA
from FABEO.fabeo22dfa import FABEO22DFA
from FABEO.waters12dfa import WATERS12DFA
import time

def measure_average_times(fe, alphabet, dfaM, x, msg,N=5):
    
    sum_setup=0
    sum_enc=0
    sum_keygen=0
    sum_dec=0

    for i in range(N):
        # setup time
        start_setup = time.time()
        (mpk, msk) = fe.setup(alphabet)
        end_setup = time.time()
        time_setup = end_setup-start_setup
        sum_setup += time_setup

        # encryption time
        start_enc = time.time()
        ctxt = fe.encrypt(mpk, x, msg)
        end_enc = time.time()
        time_enc = end_enc - start_enc
        sum_enc += time_enc

        # keygen time
        start_keygen = time.time()
        key = fe.keygen(mpk, msk, dfaM)
        end_keygen = time.time()
        time_keygen = end_keygen - start_keygen
        sum_keygen += time_keygen

        # decryption time
        start_dec = time.time()
        rec_msg = fe.decrypt(key, ctxt)
        end_dec = time.time()
        time_dec = end_dec - start_dec
        sum_dec += time_dec

        # sanity check
        if rec_msg!= msg:
            print ("Decryption failed.")
    
    # compute average time
    time_setup = sum_setup/N
    time_enc = sum_enc/N
    time_keygen = sum_keygen/N
    time_dec = sum_dec/N

    return [time_setup, time_keygen, time_enc, time_dec]

def print_running_time(scheme_name,times):
    print('{:<20}'.format(scheme_name) + format(times[0]*1000, '7.2f') + '   ' + format(times[1]*1000, '7.2f') + '  ' + format(times[2]*1000, '7.2f') + '  ' + format(times[3]*1000, '7.2f'))

def run_all(pairing_group, alphabet, regex, x_string, msg):
    dfa = DFA(regex, alphabet)
    dfaM = dfa.constructDFA()
    x = dfa.getSymbols(x_string)
    q, t, f, ell = get_par(dfaM, x)

    algos = ['Setup', 'KeyGen', 'Enc', 'Dec']

    print('Running times (ms) curve MNT224: |Q|={}  |T|={}  |F|={}  |x|={}'.format(q,t,f,ell))
    print(' - alphabet={}  regex={}  x={}'.format("(" + ", ".join(alphabet) + ")",regex,x_string))
    algo_string = 'Scheme {:<13}'.format('') + '  ' + algos[0] + '    ' + algos[1] + '     ' + algos[2] + '      ' + algos[3]
    print('-'*56)
    print(algo_string)
    print('-'*56)

    waters_dfa = WATERS12DFA(pairing_group, dfa)
    waters_dfa_times = measure_average_times(waters_dfa,alphabet,dfaM,x,msg)
    print_running_time(waters_dfa.name,waters_dfa_times)

    fabeo_dfa = FABEO22DFA(pairing_group, dfa)
    fabeo_dfa_times = measure_average_times(fabeo_dfa,alphabet,dfaM,x,msg)
    print_running_time(fabeo_dfa.name,fabeo_dfa_times)

    print('-'*56)
    print

def get_par(dfaM, x):
    Q, S, T, q0, F = dfaM
    q = len(Q)
    t = len(T)
    f = len(F)
    ell = len(x)
    return q,t,f,ell

def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT224')

    msg = pairing_group.random(GT)

    alphabet = {'a', 'b'}
    regex = "ab*a"
    x_string = "abba"

    run_all(pairing_group, alphabet, regex ,x_string, msg)

if __name__ == "__main__":
    debug = True
    main()
