openssl x509 -req \
    -in ../rsas-int/pki/reqs/servername.req \
    -CA ../rsas-int/pki/ca.crt \
    -CAkey ../rsas-int/pki/private/ca.key \
    -force_pubkey x25519.pub \
    -out x25519.crt \
    -extfile safessl-easyrsa.cnf \
    -extensions v3_req -days 10000

openssl x509 -in x25519.crt -out x25519.chain.crt
openssl x509 -in ../rsas-int/pki/ca.crt >> x25519.chain.crt
