package io.xapix.capbac;

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
    public static class Raw {
        public CapBACProto.Certificate proto;

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
            if (!payload.getParent().getPayload().isEmpty()) {
                parent = new Raw(payload.getParent()).parse();
            }

            try {
                return new CapBACCertificate(
                        payload.getCapability().toByteArray(),
                        new URL(payload.getIssuer()),
                        new URL(payload.getSubject()),
                        payload.getExpiration(),
                        parent,
                        proto.getSignature().toByteArray(),
                        this);
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
    private CapBACCertificate.Raw raw;

    CapBACCertificate(byte[] capability, URL issuer, URL subject, long exp, CapBACCertificate parent, byte[] signature, CapBACCertificate.Raw raw) {
        this.capability = capability;
        this.signature = signature;
        this.issuer = issuer;
        this.subject = subject;
        this.exp = exp;
        this.parent = parent;
        this.raw = raw;
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

    public Raw getRaw() {
        return raw;
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

    public void validate(CapBAC capbac, CapBACTrustChecker trustChecker, long now) throws CapBAC.Expired, CapBAC.Invalid, CapBAC.BadID, CapBAC.BadSign {

        for (CapBACCertificate cert : this) {
            if (cert.getExp() != 0) {
                if (cert.getExp() < now) {
                    throw new CapBAC.Expired();
                }
            }
        }
        if(!trustChecker.check(this.getRoot().getIssuer())) {
            throw new CapBAC.Invalid("Untrusted root issuer");
        }
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write( capbac.resolver.resolve(subject));
            outputStream.write( raw.proto.getPayload().toByteArray());
            if(!capbac.verify(outputStream.toByteArray(), capbac.resolver.resolve(issuer), raw.proto.getSignature().toByteArray())) {
                throw new CapBAC.BadSign();
            }
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }
}
