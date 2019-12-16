package io.xapix.capbac;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class CapBACKeypair {
    private ECPublicKey pk;
    private ECPrivateKey sk;

    public CapBACKeypair(ECPublicKey pk, ECPrivateKey sk) {
        this.pk = pk;
        this.sk = sk;
    }

    public ECPublicKey getPk() {
        return pk;
    }

    public ECPrivateKey getSk() {
        return sk;
    }
}
