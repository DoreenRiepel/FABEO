FROM ubuntu:16.04

ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

ENV LIBRARY_PATH /usr/local/lib
ENV LD_LIBRARY_PATH /usr/local/lib

RUN    apt update \
    && apt upgrade -y \
    && apt install -y locales

WORKDIR /root

RUN    apt install -y wget python python-pip
RUN    apt install -y gcc flex bison build-essential

# download and set up gmp and pbc
RUN    wget https://ftp.gnu.org/gnu/gmp/gmp-5.1.3.tar.gz
RUN    wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
RUN    tar -xf gmp-5.1.3.tar.gz
RUN    tar -xf pbc-0.5.14.tar.gz
RUN    cd gmp-5.1.3 \
    && ./configure \
    && make \
    && make install
RUN    cd pbc-0.5.14 \
    && ./configure \
    && make \
    && make install

# install packages
RUN    apt install -y libssl-dev
RUN    pip install setuptools==0.6c11
RUN    pip install pyparsing==1.5.6
RUN    pip install py==1.4.5
RUN    pip install pytest==2.2.0
RUN    pip install numpy==1.6.2

# download and set up charm
RUN    wget https://github.com/JHUISI/charm/releases/download/v0.43/Charm-Crypto-0.43_Python2.7.tar.gz
RUN    tar -xf Charm-Crypto-0.43_Python2.7.tar.gz 
RUN    cd Charm-Crypto-0.43 \
    && ./configure.sh \
    # need https here
    && sed -i "s|http|https|g" distribute_setup.py \
    && make \
    && make install \
    && ldconfig \
    && make test

# clean-up
RUN    rm gmp-5.1.3.tar.gz \
    && rm pbc-0.5.14.tar.gz \
    && rm Charm-Crypto-0.43_Python2.7.tar.gz \
    && rm -r gmp-5.1.3 \
    && rm -r pbc-0.5.14 \
    && rm -r Charm-Crypto-0.43

RUN    apt install -y git
RUN    rm /usr/local/lib/libgmp.so*

RUN    git clone https://github.com/fh15vprm49/FABEO.git


RUN    cd FABEO \
     && make \
     && pip install .

# clean-up
RUN    cd FABEO \
    && rm -r FABEO.egg-info \
    && rm -r dist \
    && rm -r build

RUN    python FABEO/samples/run_cp_schemes.py
RUN    python FABEO/samples/run_kp_schemes.py
RUN    python FABEO/samples/run_dfa_schemes.py
