package io.xapix.capbac;

import io.xapix.capbac.proto.CapBACProto;

import java.net.URL;

public interface CapBACCertificate {
    byte[] encode();
    byte[] getCapability();
    byte[] getSignature();

    CapBACCertificate getParent();
    URL getIssuer();
    URL getSubject();
    CapBACCaveat getCaveat();
}
