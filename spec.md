# CapBAC

## Operations

Protocol Operations are defined via ocaml-like interface definition syntax

```
caveat : Exp int

keypair : (pk, sk)
holder : id -> keypair -> holder
resolver : id -> pk
trust-checker : id -> boolean

forge : holder -> resolver -> subject -> capability -> caveat -> certificate
delegate : holder -> resolver -> subject -> certificate -> capability -> caveat -> certificate
invoke : holder -> certificates+ -> caveat -> action -> malformed | bad-id | invocation

check : resolver -> trust-checker -> invocation -> now -> malformed | bad-id | invalid | bad-sign | expired | (capability+, action)
```

## Structure

```

headers = issuer subject exp?

certificate = certificate? headers capability signature 
invocation = certificate+ exp? action signature
```

Headers are encoded as Protofuf v3 Message + Base64url

Capabilities and action are opaque to protocol, so they just byte arrays encoded by Base64url

## Signing

Certificate 

```
signature = sign(payload.subject-pk, issuer-sk)
```

Invocation

```
signature = sign(payload, issuer-sk)
```


## Verification

### Subject resolving



### Certificate chain

Verifier

1. Checks that root-issuers are trusted
2. Resolves subjects in certificates to subject-pks
3. Checks every certificate in chain by `(verify(payload))`


### Invocation

Verifier

1. Resolves subjects of certificate-chains to subject-pks
2. Checks that all subject-pks of top-level certificates are the same
3. Verifies invocation signature by `verify(payload, subject-pk)`
4. Verifies signatures of every certificate


## Notes

### Why not RBAC/ABAC?

### Why not other Capabilities-as-Certificate system

### Why not JWT/JWS representation
* not chain signature friendly
* freedom in protocol evolution. For example, we would consider Signature Aggregation algorithms like BLS in the future

### Why not other encoding

