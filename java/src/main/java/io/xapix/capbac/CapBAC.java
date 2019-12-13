package io.xapix.capbac;

import io.xapix.capbac.impl.CaveatImpl;
import io.xapix.capbac.impl.HolderImpl;
import io.xapix.capbac.impl.KeypairImpl;

import java.net.URL;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class CapBAC {
    public static class Error extends Throwable {
        Error() {
        }

        Error(String reason) {
            super(reason);
        }
    }
    public static class Invalid extends Error {
        public Invalid(String reason) {
            super(reason);
        }
    }

    public static class Expired extends Error {

    }

    public static class BadSign extends Error {

    }

    public static CapBACKeypair keypair(ECPublicKey pk, ECPrivateKey sk) {
        return new KeypairImpl(pk, sk);
    }

    public static CapBACHolder holder(URL me, CapBACKeypair keypair) {
        return new HolderImpl(me, keypair);
    }

    public static CapBACCaveatBuilder caveat() {
        return new CaveatImpl.Builder();
    }
}
