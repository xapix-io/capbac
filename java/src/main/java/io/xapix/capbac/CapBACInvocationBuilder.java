package io.xapix.capbac;

public interface CapBACInvocationBuilder {
    CapBACInvocationBuilder withCaveat(CapBACCaveat caveat);
    CapBACInvocationBuilder addCertificate(CapBACCertificate cert);
    CapBACInvocation build();
}
