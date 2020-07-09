package io.xapix.capbac;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.net.MalformedURLException;
import java.net.URL;

public final class CapBACInvocation {
    final CapBACProto.Invocation proto;
    final CapBACProto.Invocation.Payload payload;
    final CapBACCertificate certificate;

    public final static class Builder {
        final CapBACCertificate certificate;
        final byte[] action;
        long exp = 0;
        public Builder(CapBACCertificate certificate,  byte[] action) {
            this.certificate = certificate;
            this.action = action;
        }

        public Builder withExp(long exp) {
            this.exp = exp;
            return this;
        }
    }

    public CapBACInvocation(byte[] data) throws CapBAC.Malformed {
        try {
            this.proto = CapBACProto.Invocation.parseFrom(data);
            this.payload = CapBACProto.Invocation.Payload.parseFrom(proto.getPayload());
            this.certificate = new CapBACCertificate(payload.getCertificate());
        } catch (InvalidProtocolBufferException e) {
            throw new CapBAC.Malformed(e);
        }
    }

    CapBACInvocation(Builder builder, CapBACHolder signer) {
        CapBACProto.Invocation.Payload.Builder payloadBuilder = CapBACProto.Invocation.Payload.newBuilder();
        payloadBuilder.setInvoker(signer.me.toString());
        payloadBuilder.setAction(ByteString.copyFrom(builder.action));
        payloadBuilder.setExpiration(builder.exp);
        payloadBuilder.setCertificate(builder.certificate.getProto());

        CapBACProto.Invocation.Payload payload = payloadBuilder.build();
        ByteString payloadBytes = payload.toByteString();

        CapBACProto.Invocation.Builder protoBuilder = CapBACProto.Invocation.newBuilder();
        protoBuilder.setPayload(payloadBytes);
        protoBuilder.setSignature(ByteString.copyFrom(signer.sign(payloadBytes.toByteArray())));
        this.proto = protoBuilder.build();
        this.payload = payload;
        this.certificate = builder.certificate;
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

    public CapBACCertificate getCertificate() {
        return this.certificate;
    }

    public byte[] encode() {
        return proto.toByteArray();
    }

    public CapBACProto.Invocation getProto() {
        return proto;
    }
}
