# CapBAC

## Operations

Protocol Operations are defined via ocaml-like interface definition syntax

```
caveat : Exp int

holder : id -> sk -> holder
trust-checker : id -> boolean

forge : holder -> subject -> capability -> caveat list -> certificate
delegate : holder -> subject -> certificate -> capability -> caveat list -> certificate
invoke : holder -> certificate -> caveat* -> action -> malformed | bad-id | invocation

ids : invocation -> id list
pubkeys : id -> pk
action : invocation -> action
capabilities : invocation -> (root-id, capability list)

validator : trust-checker -> validator

validate : validator -> pubkeys -> invocation -> now -> ok | malformed | bad-id | invalid | bad-sign | expired
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

