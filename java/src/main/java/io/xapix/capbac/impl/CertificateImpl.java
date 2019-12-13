package io.xapix.capbac.impl;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.xapix.capbac.CapBAC;
import io.xapix.capbac.CapBACCaveat;
import io.xapix.capbac.CapBACCertificate;
import io.xapix.capbac.proto.CapBACProto;

import java.net.MalformedURLException;
import java.net.URL;

public class CertificateImpl implements CapBACCertificate {
    private CertificateImpl parent;
    private byte[] capability;
    private URL issuer;
    private URL subject;
    private CapBACCaveat caveat;
    private byte[] signature;

    public CertificateImpl(CertificateImpl parent, byte[] capability, URL issuer, URL subject, CapBACCaveat caveat) {
        this.parent = parent;
        this.capability = capability;
        this.issuer = issuer;
        this.subject = subject;
        this.caveat = caveat;
        this.signature = signature;
    }

    CertificateImpl(byte[] data) throws CapBAC.Invalid {
        try {
            new CertificateImpl(CapBACProto.Certificate.parseFrom(data));
        } catch (InvalidProtocolBufferException e) {
            throw new CapBAC.Invalid("Invalid format");
        }
    }

    CertificateImpl(CapBACProto.Certificate cert) throws CapBAC.Invalid {
        try {
            this.signature = cert.getSignature().toByteArray();
            CapBACProto.Certificate.Payload payload = CapBACProto.Certificate.Payload.parseFrom(cert.getPayload());
            if (payload.getParent() != null) {
                this.parent = new CertificateImpl(payload.getParent());
            }
            this.capability = payload.getCapability().toByteArray();
            this.issuer = new URL(payload.getIssuer());
            this.subject = new URL(payload.getSubject());
            if (payload.getExpiration() != 0) {
                this.caveat = new CaveatImpl(payload.getExpiration());
            }
        } catch (InvalidProtocolBufferException e) {
            throw new CapBAC.Invalid("Invalid format");
        } catch (MalformedURLException e) {
            throw new CapBAC.Invalid("Invalid id");
        }
    }

    CapBACProto.Certificate encodeProto() {
        CapBACProto.Certificate.Payload.Builder payload = CapBACProto.Certificate.Payload.newBuilder();
        if (parent != null) {
            payload.setParent(parent.encodeProto());
        }
        payload.setCapability(ByteString.copyFrom(capability));
        payload.setIssuer(issuer.toString());
        payload.setSubject(issuer.toString());
        if (caveat.expiration() != null) {
            payload.setExpiration(caveat.expiration());
        }

        CapBACProto.Certificate.Builder builder = CapBACProto.Certificate.newBuilder();
        builder.setPayload(payload.build().toByteString());
        builder.setSignature(ByteString.copyFrom(signature));
        return builder.build();
    }

    @Override
    public byte[] encode() {
        return encodeProto().toByteArray();
    }

    @Override
    public byte[] getSignature() {
        return signature;
    }

    @Override
    public CapBACCertificate getParent() {
        return parent;
    }

    @Override
    public URL getIssuer() {
        return issuer;
    }

    @Override
    public URL getSubject() {
        return subject;
    }

    @Override
    public CapBACCaveat getCaveat() {
        return caveat;
    }

    @Override
    public byte[] getCapability() {
        return capability;
    }
}
