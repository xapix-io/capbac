package io.xapix.capbac;

import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;

public class CapBACHolder {
    final URL me;
    final ECPrivateKey sk;

    public CapBACHolder(URL me, ECPrivateKey sk) {
        this.me = me;
        this.sk = sk;
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

    byte[] sign(byte[] bytes) {
        try {
            Signature signature = Signature.getInstance(CapBAC.ALG);
            signature.initSign(sk);
            signature.update(bytes);
            return signature.sign();
        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
            throw new CapBAC.SignatureError(e);
        }
    }

}
