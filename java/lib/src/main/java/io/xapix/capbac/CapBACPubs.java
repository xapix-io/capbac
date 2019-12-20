package io.xapix.capbac;

import java.net.URL;
import java.security.interfaces.ECPublicKey;

public interface CapBACPubs {
    ECPublicKey get(URL id);
}
