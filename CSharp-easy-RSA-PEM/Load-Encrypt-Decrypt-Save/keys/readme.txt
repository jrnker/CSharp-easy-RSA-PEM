RSA key to PKCS
openssl pkcs8 -topk8 -inform PEM -outform PEM -in private.key -nocrypt

Encrypt RSA key
openssl rsa -in private.key -des3

Extract RSA public key
openssl rsa -in private.key -pubout -outform PEM