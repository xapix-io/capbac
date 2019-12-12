# CapBAC

## Vocabulary
* Token
* Root Token
* Wrap Token
* Capability
* Capability Part
* ExpireAt
* CapKeyToken
* Blacksmith

HMAC-SHA256

## Token structure

Token consists of:

* Set of Capabilitites
* Validity period

token = headers capability sign
root-token = capability sign
wrap-token = headers capability cap-key sign

sign = BYTE-ARRAY
cap-key = BYTE-ARRAY

cA2.cA1.2.c.t1.s1.w.s2

["api/keys", "asdasd", "delete"]

sign = HMAC-SHA256(capability, secret)

## Operations

### Client

* restrict : token -> sub-capability -> expire-at? -> cap-key -> secret -> token
* lock : token -> key -> token

Optional:
* capability : token -> capability+
* expire-at : token -> expire-at?

### Service

* blacksmith : root-key -> (cap-key -> secret)
* forge : blacksmith -> capability -> expire-at? -> token
* inherit : blacksmith -> token -> capability -> expire-at? -> token
* check : blacksmith -> now -> lock-keys? -> token  -> invalid | bad-sign | expired | capability+


## Representation

