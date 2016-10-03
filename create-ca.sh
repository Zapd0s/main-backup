#!/bin/bash

CERT_WORKING_DIR=$(mktemp -d)
PERSIST_CFG_DIR=/cyc_var/cyc_strongswan
PERSIST_KEY_DIR=$PERSIST_CFG_DIR/etc/ipsec_keys/
NODE_CA_ID='/C=US/ST=MA/O=EMC/CN=EMC Cyclone Node CA'
NODE_ID='/C=US/ST=MA/O=EMC/CN=EMC Cyclone Node'
NODE_ID_IPSEC="$(echo $NODE_ID | sed -e's/^\///g;s/\//, /g')"

die () 
{
    echo "$@"
 #   rm -rf $CERT_WORKING_DIR
    exit 1
}

restore ()
{
    tar -xzf $PERSIST_CFG_DIR/cyc_strongswan.tgz -C / || die "Error: can't restore $PERSIST_CFG_DIR/cyc_strongswan.tgz"
    rm $PERSIST_CFG_DIR/cyc_strongswan.tgz
}

do_gen_ca_and_key () 
{
    
    echo "Checking for backup of $PERSIST_CFG_DIR"
    [ -e $PERSIST_CFG_DIR/cyc_strongswan.tgz ] && die "Error: $PERSIST_CFG_DIR/cyc_strongswan.tgz exists, remove it first"
    echo "Backing up $PERSIST_CFG_DIR ..."
    tar -czf $CERT_WORKING_DIR/cyc_strongswan.tgz $PERSIST_CFG_DIR &&
    mv $CERT_WORKING_DIR/cyc_strongswan.tgz $PERSIST_CFG_DIR || die "Can't back up $PERSIST_CFG_DIR"

    # we're doing the work in a "working dir" as there are some things that shouldn't go into
    # the strongswan/swanctl directory structure directly. 
    # we'll move the relevant bits to the right places later.
    echo "using $CERT_WORKING_DIR as cert/key gen working dir..."
    mkdir -p $CERT_WORKING_DIR/certs $CERT_WORKING_DIR/crl $CERT_WORKING_DIR/newcerts $CERT_WORKING_DIR/private $CERT_WORKING_DIR/csr &&
    chmod 700 $CERT_WORKING_DIR/private && 
    touch $CERT_WORKING_DIR/index.txt || die "Error: can't set up CERT_WORKING_DIR $CERT_WORKING_DIR"
      
    # CA serial number needs to be valid prior to creating certs; openssl will increment it on its own
    # also, it's possible that reusing the same serial to issue certs of same CN can give OpenSSL problems, so watch out for this
    local def_serial=01
    if [ -e $CERT_WORKING_DIR/serial ]; then
        cur_serial=$(cat $CERT_WORKING_DIR/serial)
        if ! [[ $cur_serial =~ ^[0-9A-F]+$ ]]; then # test that it's valid hex
            echo "Warning: current CA serial <$cur_serial> doesn't look valid, setting to default value <$def_serial>"
            echo $def_serial > $CERT_WORKING_DIR/serial
        else
            echo "Current CA serial <$cur_serial> looks ok."
        fi
    else
        echo "No CA serial number found, writing default value <$def_serial> to file..."
        echo $def_serial > $CERT_WORKING_DIR/serial
    fi

    # copy openssl.cnf from real location to here for haxx
    cp $PERSIST_KEY_DIR/openssl.cnf $CERT_WORKING_DIR/openssl.cnf || die "Error: can't get new openssl.cnf"
    # modify the openssl config to point to the right working directory
    sed -i -e "s#$PERSIST_KEY_DIR#$CERT_WORKING_DIR#g" $CERT_WORKING_DIR/openssl.cnf || die "Error: can't modify OpenSSL config"

    # The following generates a CA key/cert

    openssl genrsa -out $CERT_WORKING_DIR/private/ca.key.pem 4096 || die "Error: can't create new ca.key.pem"
    
    openssl req \
      -config $CERT_WORKING_DIR/openssl.cnf \
      -key $CERT_WORKING_DIR/private/ca.key.pem \
      -new -x509 -days 7300 -sha256 -extensions v3_ca \
      -out $CERT_WORKING_DIR/certs/ca.cert.pem -batch -subj "$NODE_CA_ID"  || die "Error: can't create ca.cert.pem"

    # This is a little clunky. The host install script puts these in the right place in cyc_var, then we copy them out 
    # to the "working dir," ? and put them back in there again? Hmm.
    #cp ${CERT_WORKING_DIR}/etc/swanctl/rsa/ca.key.pem $CERT_WORKING_DIR/private/ca.key.pem || die "Error: can't get CA key"
    #cp ${CERT_WORKING_DIR}/etc/swanctl/x509ca/ca.cert.pem $CERT_WORKING_DIR/certs/ca.cert.pem || die "Error: can't get CA cert"
    chmod 444 $CERT_WORKING_DIR/certs/ca.cert.pem &&
    chmod 400 $CERT_WORKING_DIR/private/ca.key.pem || die "Error: can't chmod CA cert and key"

    # generate private key and cert for client
    openssl genrsa \
      -out $CERT_WORKING_DIR/private/ipsec.key.pem 2048 || die "Error: creating client key"
    chmod 400 $CERT_WORKING_DIR/private/ipsec.key.pem || die "Error: can't chmod client cert"

    openssl req -config $CERT_WORKING_DIR/openssl.cnf \
      -key $CERT_WORKING_DIR/private/ipsec.key.pem \
      -new -sha256 -out $CERT_WORKING_DIR/csr/ipsec.csr.pem \
      -batch -subj "${NODE_ID}" || die "Error: creating client cert"

    # use the CA to sign the client cert
    openssl ca -config $CERT_WORKING_DIR/openssl.cnf \
      -extensions server_cert -days 3750 -notext -md sha256 \
      -in $CERT_WORKING_DIR/csr/ipsec.csr.pem \
      -out $CERT_WORKING_DIR/certs/ipsec.cert.pem -batch || die "Error: signing client cert"
    chmod 444 $CERT_WORKING_DIR/certs/ipsec.cert.pem || die "Error chmod ipsec.cert"

    # copy IPsec keys and certs from the "working directory" to the persisted store
    echo "Copying IPsec configuration from working dir to persist dir"
    cp $CERT_WORKING_DIR/certs/ca.cert.pem ${PERSIST_CFG_DIR}/etc/swanctl/x509ca/ca.cert.pem  || die "Error: CA cert copy from working dir to persist dir failed"
    cp $CERT_WORKING_DIR/private/ipsec.key.pem ${PERSIST_CFG_DIR}/etc/swanctl/rsa/ipsec.key.pem || die "Error: ipsec node key copy from working dir to persist dir failed"
    cp $CERT_WORKING_DIR/certs/ipsec.cert.pem ${PERSIST_CFG_DIR}/etc/swanctl/x509/ipsec.cert.pem || die "Error: ipsec node cert copy from working dir to persist dir failed"

    # flag to let the system know there should be IPsec config stuff already generated and don't run this again
    touch ${PERSIST_CFG_DIR}/keys_generated || die "Error: couldn't touch keys generated file"

}

[ "$1" == "restore" ] && restore || do_gen_ca_and_key
