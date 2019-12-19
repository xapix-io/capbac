package io.xapix.capbac;

import java.net.URL;
import java.security.interfaces.ECPrivateKey;

public interface CapBACKeypairs {
    ECPrivateKey get(URL id);
}
