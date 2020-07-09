package io.xapix.capbac;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;

public class CapBACValidator {
    private final CapBACTrustChecker trustChecker;
    private final CapBACPubs pubs;

    public CapBACValidator(CapBACTrustChecker trustChecker, CapBACPubs pubs) {
        this.trustChecker = trustChecker;
        this.pubs = pubs;
    }


    public void validate(CapBACCertificate cert, long now) throws CapBAC.Expired, CapBAC.Invalid, CapBAC.BadSign, CapBAC.BadID {
        for (CapBACCertificate certInChain : cert) {
            if (certInChain.getExp() != 0) {
                if (certInChain.getExp() < now) {
                    throw new CapBAC.Expired();
                }
            }
            if (certInChain.getParent() == null) {
                if(!trustChecker.check(certInChain.getRoot().getIssuer())) {
                    throw new CapBAC.Invalid("Untrusted root issuer");
                }
            }
            else {
                if (!certInChain.getParent().getSubject().equals(certInChain.getIssuer())) {
                    throw new CapBAC.Invalid(String.format("Issuer %s doesn't match subject of previous certificate in chain %s",
                            certInChain.getIssuer(),
                            certInChain.getParent().getSubject()));
                }
            }
            ECPublicKey issuerKey = pubs.get(certInChain.getIssuer());
            if (issuerKey == null) {
                throw new CapBAC.BadID(String.format("Unknown issuer %s", certInChain.getIssuer()));
            }
            if (!verify(certInChain.getProto().getPayload().toByteArray(), issuerKey, certInChain.getSignature())) {
                throw new CapBAC.BadSign(String.format("Bad sign by issuer %s", certInChain.getIssuer()));
            }
        }
    }

    public void validate(CapBACInvocation inv, long now) throws CapBAC.Invalid, CapBAC.BadID, CapBAC.BadSign, CapBAC.Expired {
        if (inv.getExp() != 0) {
            if (inv.getExp() < now) {
                throw new CapBAC.Expired();
            }
        }

        ECPublicKey invokerKey = pubs.get(inv.getInvoker());
        if (invokerKey == null) {
            throw new CapBAC.BadID(String.format("Unknown invoker %s", inv.getInvoker()));
        }

        if (!verify(inv.getProto().getPayload().toByteArray(), invokerKey, inv.getSignature())) {
            throw new CapBAC.BadSign("Bad sign by invoker");
        }

        if (!inv.getInvoker().equals(inv.getCertificate().getSubject())) {
            throw new CapBAC.Invalid("Invoker and certificate's subject don't match");
        }

        validate(inv.getCertificate(), now);
    }

    private boolean verify(byte[] data, ECPublicKey pk, byte[] signature) throws CapBAC.BadSign {
        final Signature s;
        try {
            s = Signature.getInstance(CapBAC.ALG);
            s.initVerify(pk);
            s.update(data);
            return s.verify(signature);
        } catch (NoSuchAlgorithmException e) {
            throw new CapBAC.SignatureError(e);
        } catch (SignatureException | InvalidKeyException e) {
            throw new CapBAC.BadSign(e);
        }
    }
}
