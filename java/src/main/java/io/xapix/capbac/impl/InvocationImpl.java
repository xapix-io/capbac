package io.xapix.capbac.impl;

import io.xapix.capbac.CapBACCaveat;
import io.xapix.capbac.CapBACCertificate;
import io.xapix.capbac.CapBACInvocation;
import io.xapix.capbac.CapBACResolver;
import io.xapix.capbac.proto.CapBACProto;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class InvocationImpl implements CapBACInvocation {
    private CapBACResolver resolver;
    private URL subject;
    private CapBACCaveat caveat;
    private List<CapBACCertificate> certificates = new ArrayList<CapBACCertificate>();

    public InvocationImpl(CapBACResolver resolver, URL subject, CapBACCaveat caveat, List<CapBACCertificate> certificates) {
        this.resolver = resolver;
        this.subject = subject;
        this.caveat = caveat;
        this.certificates = certificates;
    }

    @Override
    public CapBACProto.Invocation encode() {
//        CapBACProto.Invocation.Builder builder = CapBACProto.Invocation.newBuilder();
//        builder.setPayload()
        return null;
    }
}
