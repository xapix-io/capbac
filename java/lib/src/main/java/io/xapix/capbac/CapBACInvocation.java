package io.xapix.capbac;

import com.google.protobuf.InvalidProtocolBufferException;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.ListIterator;
import java.util.stream.Collectors;

public class CapBACInvocation {
    public static class Raw {
        public CapBACProto.Invocation proto;

        public Raw(byte[] data) throws CapBAC.Malformed {
            try {
                this.proto = CapBACProto.Invocation.parseFrom(data);
            } catch (InvalidProtocolBufferException e) {
                throw new CapBAC.Malformed(e);
            }
        }

        Raw(CapBACProto.Invocation proto) {
            this.proto = proto;
        }

        public byte[] encode() {
            return proto.toByteArray();
        }

        public CapBACInvocation parse() throws CapBAC.Malformed {
            CapBACProto.Invocation.Payload payload;
            try {
                payload = CapBACProto.Invocation.Payload.parseFrom(proto.getPayload());
            } catch (InvalidProtocolBufferException e) {
                throw new CapBAC.Malformed(e);
            }

            List<ProofedCert> certificates = new ArrayList<>();

            for (CapBACProto.Invocation.ProofedCertificate proto : payload.getCertificatesList()) {
                certificates.add(
                        new ProofedCert(proto,
                        proto.getSignature().toByteArray()));
            }

            try {
                return new CapBACInvocation(
                        this,
                        payload.getAction().toByteArray(),
                        new URL(payload.getInvoker()),
                        payload.getExpiration(),
                        certificates,
                        proto.getSignature().toByteArray());
            } catch (MalformedURLException e) {
                throw new CapBAC.Malformed(e);
            }
        }
    }

    public static class Builder {
        List<CapBACCertificate.Raw> certificates = new ArrayList<CapBACCertificate.Raw>();
        byte[] action;
        long exp = 0;
        public Builder( byte[] action) {
            this.action = action;
        }

        public Builder addCert(CapBACCertificate.Raw cert) {
            certificates.add(cert);
            return this;
        }

        public Builder withExp(long exp) {
            this.exp = exp;
            return this;
        }
    }

    static class ProofedCert {
        private final CapBACProto.Invocation.ProofedCertificate proto;
        CapBACCertificate.Raw raw;
        byte[] signature;

        public ProofedCert(CapBACProto.Invocation.ProofedCertificate proto, byte[] signature) throws CapBAC.Malformed {
            this.proto = proto;
            this.raw = new CapBACCertificate.Raw(proto.getPayload().toByteArray());
            this.signature = signature;
        }
    }

    private byte[] action;
    private byte[] signature;
    private long exp;
    private List<ProofedCert> certificates;
    private final Raw raw;
    private final URL invoker;

    private CapBACInvocation(Raw raw, byte[] action, URL invoker, long exp, List<ProofedCert> certificates, byte[] signature) {
        this.raw = raw;
        this.action = action;
        this.signature = signature;
        this.invoker = invoker;

        this.exp = exp;
        this.certificates = certificates;
    }

    public byte[] getAction() {
        return action;
    }

    public byte[] getSignature() {
        return signature;
    }

    public long getExp() {
        return exp;
    }

    public Raw getRaw() {
        return raw;
    }

    public URL getInvoker() {
        return invoker;
    }

    public List<CapBACCertificate.Raw> getCertificates() {
        return certificates.stream().map(x -> x.raw).collect(Collectors.toList());
    }

    public void validate(CapBAC capbac, CapBACTrustChecker trustChecker, long now) throws CapBAC.Invalid, CapBAC.BadID, CapBAC.BadSign, CapBAC.Malformed, CapBAC.Expired {
        if(certificates.size() == 0) {
            throw new CapBAC.Invalid("Invocation should contain at least one certificate");
        }

        for (ProofedCert cert : certificates) {
            CapBACCertificate parsed = cert.raw.parse();
            parsed.validate(capbac, trustChecker, now);
            if(!capbac.verify(cert.proto.getPayload().toByteArray(), capbac.resolver.resolve(parsed.getSubject()), cert.proto.getSignature().toByteArray())) {
                throw new CapBAC.BadSign();
            }
        }

        if(!capbac.verify(raw.proto.getPayload().toByteArray(), capbac.resolver.resolve(invoker), raw.proto.getSignature().toByteArray())) {
            throw new CapBAC.BadSign();
        }

    }
}
