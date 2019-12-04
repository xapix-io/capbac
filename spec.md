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

token = root-token | wrap-token
root-token = capability sign
wrap-token = headers capability cap-key sign

sign = BYTE-ARRAY
cap-key = BYTE-ARRAY

cA2.cA1.2.c.t1.s1.w.s2

["api/keys", "asdasd", "delete"]

sign = HMAC-SHA256(capability, secret)

## Operations

### Client

* wrap : token -> sub-capability -> expire-at? -> cap-key -> secret -> token

Optional:
* capability : token -> capability+
* expire-at : token -> expire-at?

### Service

* blacksmith : root-secret
* forge : blacksmith -> capability -> token
* check-root : blacksmith -> root-token -> invalid | bad-sign | capability

### Bookkeeper

* bookkeeper : (cap-key -> secret)
* check : bookkeeper -> now -> token -> invalid | bad-sign | expired | (root-token, sub-capability*)

### Utils

* check-all : bookkeeper -> blacksmith -> now -> token -> capability+

## Representation

