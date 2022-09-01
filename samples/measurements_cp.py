'''
:Date:            4/2022
'''

from charm.toolbox.pairinggroup import PairingGroup, GT
from FABEO.abgw17cp import ABGW17CPABE
from FABEO.ac17cp import AC17CPABE
from FABEO.bsw07cp import BSW07CPABE
from FABEO.cgw15cp import CGW15CPABE
from FABEO.fabeo22cp import FABEO22CPABE
from FABEO.waters11cp import Waters11CPABE
from FABEO.msp import MSP

import time

def measure_average_times(abe,attr_list,policy_str,msg,N=5):
    
    sum_setup=0
    sum_enc=0
    sum_keygen=0
    sum_dec=0

    for i in range(N):
        # setup time
        start_setup = time.time()
        (pk, msk) = abe.setup()
        end_setup = time.time()
        time_setup = end_setup-start_setup
        sum_setup += time_setup
        
        # encryption time
        start_enc = time.time()
        ctxt = abe.encrypt(pk, msg, policy_str)
        end_enc = time.time()
        time_enc = end_enc - start_enc
        sum_enc += time_enc

        # keygen time
        start_keygen = time.time()
        key = abe.keygen(pk, msk, attr_list)
        end_keygen = time.time()
        time_keygen = end_keygen - start_keygen
        sum_keygen += time_keygen

        # decryption time
        start_dec = time.time()
        rec_msg = abe.decrypt(pk, ctxt, key)
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

def run_all(pairing_group, policy_size, policy_str, attr_list, msg):
    
    algos = ['Setup', 'KeyGen', 'Enc', 'Dec']

    n1,n2,m,i = get_par(pairing_group, policy_str, attr_list)

    print('Running times (ms) curve MNT224: n1={}  n2={}  m={}  I={}'.format(n1,n2,m,i))
    algo_string = 'CP-ABE {:<13}'.format('') + '  ' + algos[0] + '    ' + algos[1] + '     ' + algos[2] + '      ' + algos[3]
    print('-'*56)
    print(algo_string)
    print('-'*56)

    bsw07_cp = BSW07CPABE(pairing_group)
    bsw07_cp_times = measure_average_times(bsw07_cp,attr_list,policy_str,msg)
    print_running_time(bsw07_cp.name,bsw07_cp_times)

    waters11_cp = Waters11CPABE(pairing_group, policy_size)
    waters11_cp_times = measure_average_times(waters11_cp,attr_list,policy_str,msg)
    print_running_time(waters11_cp.name,waters11_cp_times)

    cgw15_cp_1 = CGW15CPABE(pairing_group, 1, policy_size)
    cgw15_cp_1_times = measure_average_times(cgw15_cp_1,attr_list,policy_str,msg)
    print_running_time(cgw15_cp_1.name,cgw15_cp_1_times)

    cgw15_cp_2 = CGW15CPABE(pairing_group, 2, policy_size)
    cgw15_cp_2_times = measure_average_times(cgw15_cp_2,attr_list,policy_str,msg)
    print_running_time(cgw15_cp_2.name,cgw15_cp_2_times)

    abgw17_cp = ABGW17CPABE(pairing_group)
    abgw17_cp_times = measure_average_times(abgw17_cp,attr_list,policy_str,msg)
    print_running_time(abgw17_cp.name,abgw17_cp_times)
 
    ac17_cp = AC17CPABE(pairing_group, 2)
    ac17_cp_times = measure_average_times(ac17_cp,attr_list,policy_str,msg)
    print_running_time(ac17_cp.name,ac17_cp_times)

    fabeo22_cp = FABEO22CPABE(pairing_group)
    fabeo22_cp_times = measure_average_times(fabeo22_cp,attr_list,policy_str,msg)
    print_running_time(fabeo22_cp.name,fabeo22_cp_times)

    print('-'*56)
    print

# get parameters of the monotone span program
def get_par(pairing_group, policy_str, attr_list):
    msp_obj = MSP(pairing_group)
    policy = msp_obj.createPolicy(policy_str)
    mono_span_prog = msp_obj.convert_policy_to_msp(policy)
    nodes = msp_obj.prune(policy, attr_list)

    n1 = len(mono_span_prog) # number of rows
    n2 = msp_obj.len_longest_row # number of columns
    m = len(attr_list) # number of attributes
    i = len(nodes) # number of attributes in decryption

    return n1,n2,m,i

# create policy string and attribute list for a boolean formula of the form "1 and 2 and 3"
def create_policy_string_and_attribute_list(n):
    policy_string = '(1'
    attr_list = ['1']
    for i in range(2,n+1):
        policy_string += ' and ' + str(i)
        attr1 = str(i)
        attr_list.append(attr1)
    policy_string += ')'

    return policy_string, attr_list

def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT224')

    msg = pairing_group.random(GT)

    policy_sizes = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    for policy_size in policy_sizes:
        policy_str, attr_list = create_policy_string_and_attribute_list(policy_size)
        run_all(pairing_group, policy_size,policy_str,attr_list,msg)

if __name__ == "__main__":
    debug = True
    main()
