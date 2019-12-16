package io.xapix.capbac;

import com.google.protobuf.InvalidProtocolBufferException;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Iterator;
import java.util.stream.StreamSupport;

public class CapBACCertificate implements Iterable<CapBACCertificate> {
    public static class Raw {
        CapBACProto.Certificate proto;

        public Raw(byte[] data) throws CapBAC.Malformed {
            try {
                this.proto = CapBACProto.Certificate.parseFrom(data);
            } catch (InvalidProtocolBufferException e) {
                throw new CapBAC.Malformed(e);
            }
        }

        Raw(CapBACProto.Certificate proto) {
            this.proto = proto;
        }

        public byte[] encode() {
            return proto.toByteArray();
        }

        public CapBACCertificate parse() throws CapBAC.Malformed {
            CapBACProto.Certificate.Payload payload;
            try {
                payload = CapBACProto.Certificate.Payload.parseFrom(proto.getPayload());
            } catch (InvalidProtocolBufferException e) {
                throw new CapBAC.Malformed(e);
            }

            CapBACCertificate parent = null;
            if (payload.getParent() != null) {
                parent = new Raw(payload.getParent()).parse();
            }

            try {
                return new CapBACCertificate(
                        payload.getCapability().toByteArray(),
                        new URL(payload.getIssuer()),
                        new URL(payload.getSubject()),
                        payload.getExpiration(),
                        parent,
                        proto.getSignature().toByteArray());
            } catch (MalformedURLException e) {
                throw new CapBAC.Malformed(e);
            }
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

    private byte[] capability;
    private byte[] signature;
    private URL issuer;
    private URL subject;
    private long exp;
    private CapBACCertificate parent;

    CapBACCertificate(byte[] capability, URL issuer, URL subject, long exp, CapBACCertificate parent, byte[] signature) {
        this.capability = capability;
        this.signature = signature;
        this.issuer = issuer;
        this.subject = subject;
        this.exp = exp;
        this.parent = parent;
    }

    public byte[] getCapability() {
        return capability;
    }

    public byte[] getSignature() {
        return signature;
    }

    public URL getIssuer() {
        return issuer;
    }

    public URL getSubject() {
        return subject;
    }

    public long getExp() {
        return exp;
    }

    public CapBACCertificate getParent() {
        return parent;
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
                return next;
            }
        };
    }

    public CapBACCertificate getRoot() {
        return StreamSupport.stream(this.spliterator(), false).reduce((first, second) -> second).get();
    }
}
