package io.xapix.capbac;

public interface CapBACCaveatBuilder {
    CapBACCaveatBuilder withExpiration(long expireAt);
    CapBACCaveat build();
}
