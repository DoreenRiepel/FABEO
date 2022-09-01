'''
:Date:            4/2022
'''

from charm.toolbox.pairinggroup import PairingGroup, GT
from FABEO.abgw17kp import ABGW17KPABE
from FABEO.ac17kp import AC17KPABE
from FABEO.cgw15kp import CGW15KPABE
from FABEO.fabeo22kp import FABEO22KPABE
from FABEO.gpsw06kp import GPSW06KPABE


def run_kpabe(abe, attr_list, policy_str, msg):
    (mpk, msk) = abe.setup()
    key = abe.keygen(mpk, msk, policy_str)
    ctxt = abe.encrypt(mpk, msg, attr_list)
    rec_msg = abe.decrypt(mpk, ctxt, key)
    
    if debug:
        if rec_msg == msg:
            print("Successful decryption for {}.".format(abe.name))
        else:
            print("Decryption failed for {}.".format(abe.name))

def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT224')

    attr_list = ['1', '2', '3']
    policy_str = '((1 and 3) and (2 OR 4))'

    # choose a random message
    msg = pairing_group.random(GT)

    gpsw06_kp = GPSW06KPABE(pairing_group, 10)
    run_kpabe(gpsw06_kp, attr_list, policy_str, msg)

    cgw15_kp = CGW15KPABE(pairing_group, 2, 10)
    run_kpabe(cgw15_kp, attr_list, policy_str, msg)

    abgw17_kp = ABGW17KPABE(pairing_group)
    run_kpabe(abgw17_kp, attr_list, policy_str, msg)
    
    ac17_kp = AC17KPABE(pairing_group, 2)
    run_kpabe(ac17_kp, attr_list, policy_str, msg)

    fabeo22_kp = FABEO22KPABE(pairing_group)
    run_kpabe(fabeo22_kp, attr_list, policy_str, msg)

if __name__ == "__main__":
    debug = True
    main()
