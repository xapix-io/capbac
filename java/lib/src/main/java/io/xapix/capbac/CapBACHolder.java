package io.xapix.capbac;

import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

public class CapBACHolder {
    URL me;
    private CapBACKeypairs keypairs;

    public CapBACHolder(URL me, CapBACKeypairs keypairs) {
        this.me = me;
        this.keypairs = keypairs;
    }

    public CapBACCertificate forge(CapBACCertificate.Builder builder) {
        return new CapBACCertificate(builder, this);
    }

    public CapBACCertificate delegate(CapBACCertificate cert, CapBACCertificate.Builder builder) {
        return new CapBACCertificate(cert, builder, this);
    }

    public CapBACInvocation invoke(CapBACInvocation.Builder builder) {
        return new CapBACInvocation(builder, this);
    }

    byte[] sign(URL issuer, byte[] bytes) {
        try {
            Signature signature = Signature.getInstance(CapBAC.ALG);
            signature.initSign(keypairs.get(issuer));
            signature.update(bytes);
            return signature.sign();
        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
            throw new CapBAC.SignatureError(e);
        }
    }

    byte[] sign(byte[] bytes) {
        return sign(me, bytes);
    }

}
