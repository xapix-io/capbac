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
* Capability is a hiearachial list which represents rights to execute some particular action
* Validity period

Token = (RootToken | WrapToken) Sign

RootToken {
  Capability = BYTE-ARRAY*
  ExpireAt? = NUMBER
}

WrapToken {
  Token = Token
  CapabilityRestriction = BYTE-ARRAY*
  CapKeyToken = Token
  ExpireAt? = NUMBER
}

r[oot-token]/2
w[rap-token]/3
c[apability]/n

token[t] = root-token | wrap-token
root-token = capability sign
wrap-token = token cap-key sign

sign = BYTE-ARRAY
cap-key = BYTE-ARRAY

cA2.cA1.2.c.t1.s1.w.s2

["api/keys", "asdasd", "delete"]

sign = HMAC-SHA256(capability, secret)

## Operations

### Client

* wrap : token -> sub-capability -> sub-expiration? -> cap-key-token -> secret -> token
* capability : token -> capability
* expire-at : token -> expire-at?

### Service

* blacksmith : root-secret
* forge : blacksmith -> capability -> expiration? -> token
* check : blacksmith -> now -> token -> capability -> invalid | expired | non-authorized | ok

### Bookkeeper

* 

## Capability verification

## Representation

### ASCII
