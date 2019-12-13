package io.xapix.capbac;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public interface CapBACKeypair {
    ECPublicKey getPK();
    ECPrivateKey getSK();
}
