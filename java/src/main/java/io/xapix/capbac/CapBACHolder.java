package io.xapix.capbac;

import java.net.URL;

public interface CapBACHolder {
    CapBACCertificate forge(CapBACResolver resolver, URL subject, byte[] capability);
    CapBACCertificate forge(CapBACResolver resolver, URL subject, byte[] capability, CapBACCaveat caveat);
//
//    CapBACCertificate delegate(CapBACCertificate cert, CapBACResolver resolver, URL subject, byte[] subCapability);
//    CapBACCertificate delegate(CapBACCertificate cert, CapBACResolver resolver, URL subject, byte[] subCapability, CapBACCaveat caveat);
//    CapBACInvocationBuilder invoke(CapBACResolver resolver, URL subject);
}
