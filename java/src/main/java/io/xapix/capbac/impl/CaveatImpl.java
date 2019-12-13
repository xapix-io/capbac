package io.xapix.capbac.impl;

import io.xapix.capbac.CapBACCaveat;
import io.xapix.capbac.CapBACCaveatBuilder;

public class CaveatImpl implements CapBACCaveat {
    private long expiration;
    public static class Builder implements CapBACCaveatBuilder {
        private long expiration;
        @Override
        public CapBACCaveatBuilder withExpiration(long expireAt) {
            this.expiration = expireAt;
            return this;
        }

        @Override
        public CapBACCaveat build() {
            return new CaveatImpl(expiration);
        }
    }

    public CaveatImpl(long expiration) {
        this.expiration = expiration;
    }

    @Override
    public Long expiration() {
        return this.expiration;
    }
}
