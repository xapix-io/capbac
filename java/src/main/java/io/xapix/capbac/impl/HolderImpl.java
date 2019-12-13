package io.xapix.capbac.impl;

import io.xapix.capbac.*;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class HolderImpl implements CapBACHolder {

    private URL me;
    private CapBACKeypair keypair;

    public HolderImpl(URL me, CapBACKeypair keypair) {
        this.me = me;
        this.keypair = keypair;
    }

    @Override
    public CapBACCertificate forge(CapBACResolver resolver, URL subject, byte[] capability) {
        return forge( resolver, subject, capability);
    }

    @Override
    public CapBACCertificate forge(CapBACResolver resolver, URL subject, byte[] capability, CapBACCaveat caveat) {
        return new CertificateImpl(null, capability, me, subject, caveat);
    }
//
//    @Override
//    public CapBACCertificate delegate(CapBACCertificate cert, CapBACResolver resolver, URL subject, byte[] subCapability) {
//        return null;
//    }
//
//    @Override
//    public CapBACCertificate delegate(CapBACCertificate cert, CapBACResolver resolver, URL subject, byte[] subCapability, CapBACCaveat caveat) {
//        return null;
//    }
//
//
//
//    private static class InvocationBuilder implements CapBACInvocationBuilder {
//        private CapBACResolver resolver;
//        private URL subject;
//        private CapBACCaveat caveat;
//        private List<CapBACCertificate> certificates = new ArrayList<CapBACCertificate>();
//        InvocationBuilder(CapBACResolver resolver, URL subject) {
//            this.resolver = resolver;
//            this.subject = subject;
//        }
//        @Override
//        public CapBACInvocationBuilder withCaveat(CapBACCaveat caveat) {
//            this.caveat = caveat;
//            return this;
//        }
//
//        @Override
//        public CapBACInvocationBuilder addCertificate(CapBACCertificate cert) {
//            certificates.add(cert);
//                    return this;
//        }
//
//        @Override
//        public InvocationImpl build() {
//            return ;
//        }
//    }
//
//    @Override
//    public CapBACInvocationBuilder invoke(CapBACResolver resolver, URL subject) {
//        return null;
//    }
}
