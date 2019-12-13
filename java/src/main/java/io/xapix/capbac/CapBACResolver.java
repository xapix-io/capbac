package io.xapix.capbac;

import java.net.URL;
import java.security.interfaces.ECPublicKey;

public interface CapBACResolver {
    ECPublicKey resolve(URL id);
}
