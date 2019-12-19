package io.xapix.capbac;

import com.google.protobuf.ByteString;
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
    CapBACProto.Invocation proto;
    CapBACProto.Invocation.Payload payload;

    public static class Builder {
        List<CapBACCertificate> certificates = new ArrayList<>();
        byte[] action;
        long exp = 0;
        public Builder( byte[] action) {
            this.action = action;
        }

        public Builder addCert(CapBACCertificate cert) {
            certificates.add(cert);
            return this;
        }

        public Builder withExp(long exp) {
            this.exp = exp;
            return this;
        }
    }

    static class ProofedCert {
        final CapBACProto.Invocation.ProofedCertificate proto;
        CapBACCertificate cert;

        ProofedCert(CapBACProto.Invocation.ProofedCertificate proto) throws CapBAC.Malformed {
            this.proto = proto;
            this.cert = new CapBACCertificate(proto.getPayload().toByteArray());
        }

        public ProofedCert(CapBACProto.Invocation.ProofedCertificate proto, CapBACCertificate cert) {
            this.proto = proto;
            this.cert = cert;
        }
    }

    private List<ProofedCert> certificates = new ArrayList<>();

    public CapBACInvocation(byte[] data) throws CapBAC.Malformed {
        try {
            this.proto = CapBACProto.Invocation.parseFrom(data);
            this.payload = CapBACProto.Invocation.Payload.parseFrom(proto.getPayload());
            for (CapBACProto.Invocation.ProofedCertificate pCert : payload.getCertificatesList()) {
                certificates.add(new ProofedCert(pCert));
            }
        } catch (InvalidProtocolBufferException e) {
            throw new CapBAC.Malformed(e);
        }
    }

    CapBACInvocation(Builder builder, CapBACHolder signer) {
        CapBACProto.Invocation.Payload.Builder payloadBuilder = CapBACProto.Invocation.Payload.newBuilder();
        payloadBuilder.setInvoker(signer.me.toString());
        payloadBuilder.setAction(ByteString.copyFrom(builder.action));
        payloadBuilder.setExpiration(builder.exp);
        for (CapBACCertificate cert : builder.certificates) {
            CapBACProto.Invocation.ProofedCertificate.Builder certBuilder = CapBACProto.Invocation.ProofedCertificate.newBuilder();
            ByteString certBytes = cert.proto.toByteString();
            certBuilder.setPayload(certBytes);
            certBuilder.setSignature(ByteString.copyFrom(signer.sign(cert.getSubject(), certBytes.toByteArray())));
            CapBACProto.Invocation.ProofedCertificate proofedCert = certBuilder.build();
            payloadBuilder.addCertificates(proofedCert);
            this.certificates.add(new ProofedCert(proofedCert, cert));
        }

        CapBACProto.Invocation.Payload payload = payloadBuilder.build();
        ByteString payloadBytes = payload.toByteString();

        CapBAC.runtimeCheck(builder.certificates.size() > 0, "Invocation should include at least one certificate");

        CapBACProto.Invocation.Builder protoBuilder = CapBACProto.Invocation.newBuilder();
        protoBuilder.setPayload(payloadBytes);
        protoBuilder.setSignature(ByteString.copyFrom(signer.sign(payloadBytes.toByteArray())));
        this.proto = protoBuilder.build();
        this.payload = payload;
    }

    public byte[] getAction() {
        return payload.getAction().toByteArray();
    }

    public byte[] getSignature() {
        return proto.getSignature().toByteArray();
    }

    public long getExp() {
        return payload.getExpiration();
    }

    public URL getInvoker() {
        try {
            return new URL(payload.getInvoker());
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    public List<CapBACCertificate> getCertificates() {
        return certificates.stream().map(x -> x.cert).collect(Collectors.toList());
    }

    public List<ProofedCert> getProofs() {
        return certificates;
    }

    public byte[] encode() {
        return proto.toByteArray();
    }

    public CapBACProto.Invocation getProto() {
        return proto;
    }
}
