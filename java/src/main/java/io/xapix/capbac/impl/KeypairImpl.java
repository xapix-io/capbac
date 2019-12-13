package io.xapix.capbac.impl;

import io.xapix.capbac.CapBACKeypair;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class KeypairImpl implements CapBACKeypair {

    private ECPublicKey pk;
    private ECPrivateKey sk;

    public KeypairImpl(ECPublicKey pk, ECPrivateKey sk) {
        this.pk = pk;
        this.sk = sk;
    }

    public ECPublicKey getPK() {
        return pk;
    }

    public ECPrivateKey getSK() {
        return sk;
    }
}
