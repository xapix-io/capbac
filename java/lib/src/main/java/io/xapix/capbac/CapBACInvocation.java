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
        CapBACProto.Invocation proto;

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

            List<CapBACCertificate.Raw> certificates = new ArrayList<CapBACCertificate.Raw>();

            for (CapBACProto.Certificate proto : payload.getCertificatesList()) {
                certificates.add(new CapBACCertificate.Raw(proto));
            }

            return new CapBACInvocation(
                    payload.getAction().toByteArray(),
                    payload.getExpiration(),
                    certificates,
                    proto.getSignature().toByteArray());
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

    private byte[] action;
    private byte[] signature;
    private long exp;
    private List<CapBACCertificate.Raw> certificates;

    CapBACInvocation(byte[] action, long exp, List<CapBACCertificate.Raw> certificates, byte[] signature) {
        this.action = action;
        this.signature = signature;

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

    public List<CapBACCertificate.Raw> getCertificates() {
        return certificates;
    }

    public void validate(CapBAC capbac, CapBACTrustChecker trustChecker, long now) throws CapBAC.Invalid, CapBAC.BadID, CapBAC.BadSign, CapBAC.Malformed, CapBAC.Expired {
        if(certificates.size() == 0) {
            throw new CapBAC.Invalid("Invocation should contain at least one certificate");
        }
        List<byte[]> resolvedSubjects = new ArrayList<>();

        for (CapBACCertificate.Raw rawCert : certificates) {
            CapBACCertificate parsed = rawCert.parse();

            for (CapBACCertificate cert : parsed) {
                if (cert.getExp() != 0) {
                    if (cert.getExp() < now) {
                        throw new CapBAC.Expired();
                    }
                }
            }

            byte[] resolve = capbac.resolver.resolve(parsed.getSubject());
            resolvedSubjects.add(resolve);

            if(!trustChecker.check(parsed.getRoot().getIssuer())) {
                throw new CapBAC.Invalid("Untrusted root issuer");
            }
        }

        byte[] subject = resolvedSubjects.get(0);
        for (ListIterator<byte[]> it = resolvedSubjects.listIterator(1); it.hasNext(); ) {
            byte[] subj1 = it.next();
            if (!Arrays.equals(subj1, subject)) {
                throw new CapBAC.Invalid("Subjects of certificates are not the same");
            }
        }

        for (CapBACCertificate.Raw rawCert : certificates) {
            if(!verify(capbac, rawCert.proto.getPayload().toByteArray(), subject, rawCert.proto.getSignature().toByteArray())) {
                throw new CapBAC.BadSign();
            }
        }
    }

    private boolean verify(CapBAC capbac, byte[] data, byte[] pk, byte[] signature) throws CapBAC.BadID, CapBAC.BadSign {
        final Signature s;
        try {
            s = Signature.getInstance(capbac.ALG);

            s.initVerify(capbac.bytesToPK(pk));
            s.update(data);
            return s.verify(signature);
        } catch (NoSuchAlgorithmException e) {
            throw new CapBAC.SignatureError(e);
        } catch (SignatureException | InvalidKeyException e) {
            throw new CapBAC.BadSign(e);
        }
    }
}
