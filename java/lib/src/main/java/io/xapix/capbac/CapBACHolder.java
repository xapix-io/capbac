package io.xapix.capbac;

import com.google.protobuf.ByteString;

import java.net.URL;
import java.security.*;
import java.security.interfaces.ECPrivateKey;

public class CapBACHolder {
    private URL me;
    private CapBAC capbac;
    private CapBACKeypairs keypairs;

    public CapBACHolder(URL me, CapBAC capbac, CapBACKeypairs keypairs) {
        this.me = me;
        this.capbac = capbac;
        this.keypairs = keypairs;
    }

    public CapBACCertificate.Raw forge(CapBACCertificate.Builder builder) throws CapBAC.BadID {
        CapBACProto.Certificate.Payload.Builder payloadBuilder = certBuilderToProto(builder);
        CapBACProto.Certificate.Payload payload = payloadBuilder.build();
        CapBACProto.Certificate.Builder certBuilder = CapBACProto.Certificate.newBuilder();
        ByteString payloadBytes = payload.toByteString();

        certBuilder.setPayload(payloadBytes);
        certBuilder.setSignature(ByteString.copyFrom(makeSignature(builder.subject, payloadBytes.toByteArray())));
        return new CapBACCertificate.Raw(certBuilder.build());
    }

    public CapBACCertificate.Raw delegate(CapBACCertificate.Raw cert, CapBACCertificate.Builder builder) throws CapBAC.BadID {
        CapBACProto.Certificate.Payload.Builder payloadBuilder = certBuilderToProto(builder);

        payloadBuilder.setParent(cert.proto);

        CapBACProto.Certificate.Payload payload = payloadBuilder.build();
        CapBACProto.Certificate.Builder certBuilder = CapBACProto.Certificate.newBuilder();
        ByteString payloadBytes = payload.toByteString();

        certBuilder.setPayload(payloadBytes);
        certBuilder.setSignature(ByteString.copyFrom(makeSignature(builder.subject, payloadBytes.toByteArray())));
        return new CapBACCertificate.Raw(certBuilder.build());
    }

    public CapBACInvocation.Raw invoke(CapBACInvocation.Builder builder) throws CapBAC.BadID, CapBAC.Malformed {
        CapBACProto.Invocation.Payload.Builder payloadBuilder = CapBACProto.Invocation.Payload.newBuilder();
        payloadBuilder.setInvoker(me.toString());
        payloadBuilder.setAction(ByteString.copyFrom(builder.action));
        payloadBuilder.setExpiration(builder.exp);
        for (CapBACCertificate.Raw cert : builder.certificates) {
            CapBACProto.Invocation.ProofedCertificate.Builder certBuilder = CapBACProto.Invocation.ProofedCertificate.newBuilder();
            ByteString certBytes = cert.proto.toByteString();
            certBuilder.setPayload(certBytes);
            certBuilder.setSignature(ByteString.copyFrom(makeSignature(cert.parse().getSubject(), certBytes.toByteArray())));
            payloadBuilder.addCertificates(certBuilder);
        }

        CapBACProto.Invocation.Payload payload = payloadBuilder.build();
        CapBACProto.Invocation.Builder invBuilder = CapBACProto.Invocation.newBuilder();
        ByteString payloadBytes = payload.toByteString();

        CapBAC.runtimeCheck(builder.certificates.size() > 0, "Invocation should include at least one certificate");

        invBuilder.setPayload(payloadBytes);
        invBuilder.setSignature(ByteString.copyFrom(makeSignature(payloadBytes.toByteArray())));
        return new CapBACInvocation.Raw(invBuilder.build());
    }

    private CapBACProto.Certificate.Payload.Builder certBuilderToProto(CapBACCertificate.Builder builder) {
        CapBACProto.Certificate.Payload.Builder payloadBuilder = CapBACProto.Certificate.Payload.newBuilder();
        payloadBuilder.setCapability(ByteString.copyFrom(builder.capability));
        payloadBuilder.setExpiration(builder.exp);
        payloadBuilder.setSubject(builder.subject.toString());
        payloadBuilder.setIssuer(me.toString());
        return payloadBuilder;
    }

    private byte[] makeSignature(byte[] bytes) {
        try {
            Signature signature = Signature.getInstance(capbac.ALG);
            signature.initSign(keypairs.get(me));
            signature.update(bytes);
            return signature.sign();
        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | CapBAC.BadID e) {
            throw new CapBAC.SignatureError(e);
        }
    }

    private byte[] makeSignature(URL subject, byte[] bytes) throws CapBAC.BadID {
        try {
            Signature signature = Signature.getInstance(capbac.ALG);
            signature.initSign(keypairs.get(me));
            signature.update(capbac.resolver.resolve(subject));
            signature.update(bytes);
            return signature.sign();
        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
            throw new CapBAC.SignatureError(e);
        }
    }


}
