package io.xapix.capbac;

import com.google.protobuf.ByteString;

import java.net.URL;
import java.security.*;

public class CapBACHolder {
    private URL me;
    private CapBACKeypair keypair;
    private CapBAC capbac;

    public CapBACHolder(URL me, CapBACKeypair keypair, CapBAC capbac) {
        this.me = me;
        this.capbac = capbac;
        this.keypair = keypair;
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

    public CapBACInvocation.Raw invoke(CapBACInvocation.Builder builder) throws CapBAC.BadID {
        CapBACProto.Invocation.Payload.Builder payloadBuilder = CapBACProto.Invocation.Payload.newBuilder();
        payloadBuilder.setAction(ByteString.copyFrom(builder.action));
        payloadBuilder.setExpiration(builder.exp);
        for (CapBACCertificate.Raw cert : builder.certificates) {
            payloadBuilder.addCertificates(cert.proto);
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

    private byte[] makeSignature(byte[] bytes) throws CapBAC.BadID {
        try {
            Signature signature = Signature.getInstance(capbac.ALG);
            signature.initSign(keypair.getSk());
            signature.update(bytes);
            return signature.sign();
        } catch (InvalidKeyException e) {
            throw new CapBAC.SignatureError(e);
        } catch (NoSuchAlgorithmException e) {
            throw new CapBAC.SignatureError(e);
        } catch (SignatureException e) {
            throw new CapBAC.SignatureError(e);
        }
    }

    private byte[] makeSignature(URL subject, byte[] bytes) throws CapBAC.BadID {
        try {
            Signature signature = Signature.getInstance(capbac.ALG);
            signature.initSign(keypair.getSk());
            signature.update(capbac.resolver.resolve(subject));
            signature.update(bytes);
            return signature.sign();
        } catch (InvalidKeyException e) {
            throw new CapBAC.SignatureError(e);
        } catch (NoSuchAlgorithmException e) {
            throw new CapBAC.SignatureError(e);
        } catch (SignatureException e) {
            throw new CapBAC.SignatureError(e);
        }
    }


}
