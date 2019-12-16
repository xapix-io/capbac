package io.xapix.capbac;

import java.net.URL;

public interface CapBACTrustChecker {
    boolean check(URL id);
}
