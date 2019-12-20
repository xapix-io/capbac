package io.xapix.capbac;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Iterator;
import java.util.stream.StreamSupport;

public class CapBACCertificate implements Iterable<CapBACCertificate> {
    final CapBACProto.Certificate proto;
    final CapBACProto.Certificate.Payload payload;
    public CapBACCertificate(byte[] data) throws CapBAC.Malformed {
        try {
            this.proto = CapBACProto.Certificate.parseFrom(data);
            this.payload = CapBACProto.Certificate.Payload.parseFrom(proto.getPayload());
        } catch (InvalidProtocolBufferException e) {
            throw new CapBAC.Malformed(e);
        }
    }

    public static class Builder {
        URL subject;
        byte[] capability;
        long exp = 0;
        public Builder(URL subject, byte[] capability) {
            this.subject = subject;
            this.capability = capability;
        }

        public Builder withExp(long exp) {
            this.exp = exp;
            return this;
        }
    }

    CapBACCertificate(CapBACProto.Certificate proto) {
        this.proto = proto;
        try {
            this.payload = CapBACProto.Certificate.Payload.parseFrom(proto.getPayload());
        } catch (InvalidProtocolBufferException e) {
            throw new RuntimeException(e);
        }
    }

    CapBACCertificate(Builder builder, CapBACHolder signer) {
        this(null, builder, signer);
    }

    CapBACCertificate(CapBACCertificate parent, Builder builder, CapBACHolder signer) {
        CapBACProto.Certificate.Payload.Builder payloadBuilder = CapBACProto.Certificate.Payload.newBuilder();
        payloadBuilder.setCapability(ByteString.copyFrom(builder.capability));
        payloadBuilder.setExpiration(builder.exp);
        payloadBuilder.setSubject(builder.subject.toString());
        payloadBuilder.setIssuer(signer.me.toString());
        if (parent != null) {
            payloadBuilder.setParent(parent.proto);
        }

        CapBACProto.Certificate.Payload payload = payloadBuilder.build();
        ByteString payloadBytes = payload.toByteString();

        CapBACProto.Certificate.Builder protoBuilder = CapBACProto.Certificate.newBuilder();
        protoBuilder.setPayload(payloadBytes);
        protoBuilder.setSignature(ByteString.copyFrom(signer.sign(payloadBytes.toByteArray())));
        this.proto = protoBuilder.build();
        this.payload = payload;
    }

    public byte[] getCapability() {
        return payload.getCapability().toByteArray();
    }

    public byte[] getSignature() {
        return proto.getSignature().toByteArray();
    }

    public URL getIssuer() {
        try {
            return new URL(payload.getIssuer());
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    public URL getSubject() {
        try {
            return new URL(payload.getSubject());
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    public long getExp() {
        return payload.getExpiration();
    }

    public CapBACCertificate getParent() {
        if (!payload.getParent().getPayload().isEmpty()) {
            return new CapBACCertificate(payload.getParent());
        } else {
            return null;
        }
    }

    @Override
    public Iterator<CapBACCertificate> iterator() {
        return new Iterator<CapBACCertificate>() {
            private CapBACCertificate next = CapBACCertificate.this;
            @Override
            public boolean hasNext() {
                if (next != null) {
                    return true;
                }
                return false;
            }

            @Override
            public CapBACCertificate next() {
                CapBACCertificate prev = next;
                next = prev.getParent();
                return prev;
            }
        };
    }

    public CapBACCertificate getRoot() {
        return StreamSupport.stream(this.spliterator(), false).reduce((first, second) -> second).get();
    }

    public byte[] encode() {
        return proto.toByteArray();
    }

    public CapBACProto.Certificate getProto() {
        return proto;
    }
}
