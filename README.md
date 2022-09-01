# FABEO: Fast Attribute-based Encryption with Optimal Security
 
This is the code repository accompanying our CCS '22 paper "FABEO: Fast Attribute-based Encryption with Optimal Security" by Doreen Riepel and Hoeteck Wee.


> Attribute-based encryption (ABE) enables fine-grained access control on encrypted data and has a large number of practical applications. This paper presents FABEO: fasterpairing-based ciphertext-policy and key-policy ABE schemes that support expressive policies and put no restriction on policy type or attributes, and the first to achieve optimal, adaptive security with multiple challenge ciphertexts. We implement our schemes and demonstrate that they perform better than the state-of-the-art (Bethencourt et al. S&P 2007, Agrawal et al., CCS 2017 and Ambrona et al., CCS 2017) on all parameters of practical interest.


## Schemes

The code uses the Charm library and Python and builds upon the code of [FAME](https://github.com/sagrawal87/ABE), which provides implementations of their CP-ABE scheme FAME [1, Section 3] as well as those by BSW [3, Section 4.2], CGW [4, Appendix B.2] and Waters [6, Section 3]. We extend this code by our FABEO CP-ABE and KP-ABE schemes as well as the extention to DFA. For our benchmarks, we also implemented the following schemes:

- ABGW CP-ABE [2, Section 5.3]
- ABGW KP-ABE [2, Section 5.3]
- CGW KP-ABE [x, Appendix B.1]
- FAME KP-ABE [1, Appendix B]
- GPSW KP-ABE [5, Appendix A.1]
- Waters ABE for DFA [7, Section 3]

All schemes are implemented using asymmetric pairing groups. For the Waters DFA scheme we transfer the existing code from [here](https://jhuisi.github.io/charm/_modules/dfa_fe12.html#FE_DFA) to this setting.

Some of the schemes are bounded universe, i.e. they support an a-priori bounded number of attributes. To initialize such schemes, an additional parameter `uni_size` needs to be specified. Some schemes are secure under the k-linear family of assumptions, so k must be set properly during initialization through the parameter `assump_size`.

## Quick Install & Test

The schemes have been tested with Charm 0.43 and Python 2.7.12 on Ubuntu 16.04. (Note that Charm may not compile on newer Linux systems due to the incompatibility of OpenSSL versions 1.0 and 1.1.).

We provide a Dockerfile that installs all necessary libraries and packages. Docker can be installed from [here](https://docs.docker.com/get-docker/). On Linux, the container can be built using the command
```sh
docker build -t fabeo .
```
which will also run all the implemented schemes. To run our test files individually, run the Docker container in interactive mode using
```sh
docker run -it fabeo
```
To run one instance of each CP-ABE scheme use

```sh
cd FABEO && python samples/run_cp_schemes.py
```
Replace `cp` by `kp` or `dfa` to run the other schemes. We also provide the code we used for the benchmarks in our submission. They can be run using `python samples/measurements_xx` for `xx={cp,kp}` and will print the running times in milliseconds. In our paper, we compute the average running time for 20 executions. This parameter can be specified as input to the `measure_average_times` function.


## Manual Installation

Charm 0.43 can also be installed directly from [this](https://github.com/JHUISI/charm/releases) page, or by running

```sh
pip install -r requirements.txt
```
Once you have Charm, run
```sh
make && pip install . && python samples/run_cp_schemes.py
```

## References

[1] S. Agrawal and M. Chase. FAME: Fast attribute-based message encryption. In B. M. Thuraisingham, D. Evans, T. Malkin, and D. Xu, editors, ACM CCS 2017, pages 665–682. ACM Press, Oct. / Nov. 2017.

[2] M. Ambrona, G. Barthe, R. Gay, and H. Wee. Attribute-based encryption in the generic group model: Automated proofs and new constructions. In B. M. Thuraisingham, D. Evans, T. Malkin, and D. Xu, editors, ACM CCS 2017, pages 647–664. ACM Press, Oct. / Nov. 2017.

[3] J. Bethencourt, A. Sahai, and B.Waters. Ciphertext-policy attribute-based encryption. In 2007 IEEE Symposium on Security and Privacy, pages 321–334. IEEE Computer Society Press, May 2007.

[4] J. Chen, J. Gong, and J. Weng. Tightly secure IBE under constant-size master public key. In S. Fehr, editor, PKC 2017, Part I, volume 10174 of LNCS, pages 207–231. Springer, Heidelberg, Mar. 2017.

[5] V. Goyal, O. Pandey, A. Sahai, and B. Waters. Attribute-based encryption for fine-grained access control of encrypted data. In A. Juels, R. N. Wright, and S. De Capitani di Vimercati, editors, ACM CCS 2006, pages 89–98. ACM Press, Oct. / Nov. 2006. Available as Cryptology ePrint Archive Report 2006/309.

[6] B. Waters. Ciphertext-policy attribute-based encryption: An expressive, efficient, and provably secure realization. In D. Catalano, N. Fazio, R. Gennaro, and A. Nicolosi, editors, PKC 2011, volume 6571 of LNCS, pages 53–70. Springer, Heidelberg, Mar. 2011.

[7] B. Waters. Functional encryption for regular languages. In R. Safavi-Naini and R. Canetti, editors, CRYPTO 2012, volume 7417 of LNCS, pages 218–235. Springer, Heidelberg, Aug. 2012.