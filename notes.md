# Generate keys

```bash
# private key
openssl ecparam -genkey -name prime256v1 -noout -out ec_private.pem

# convert to pkcs8 format
openssl pkcs8 -topk8 -inform PEM -outform DER -in ec_private.pem -nocrypt > ec_private.pk8

# generate public key
openssl pkey -pubout -inform der -outform der -in ec_private.pk8 -out ec_public.der
```
