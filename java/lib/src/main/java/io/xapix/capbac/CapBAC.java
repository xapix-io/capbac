package io.xapix.capbac;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.IOException;
import java.io.Reader;
import java.net.URL;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class CapBAC {
    String ALG = "SHA256withECDSA";
    CapBACResolver resolver;
    CapBACKeypairs keypairs;

    public CapBAC(CapBACResolver resolver, CapBACKeypairs keypairs) {
        this.keypairs = keypairs;
        this.resolver = resolver;
    }

    public static class SignatureError extends RuntimeException{
        public SignatureError(Throwable cause) {
            super(cause);
        }
    }

    public static class Error extends Throwable {
        Error() {
        }

        Error(Throwable cause) {
            super(cause);
        }

        Error(String msg) {
            super(msg);
        }
    }
    public static class Malformed extends Error {
        public Malformed(Throwable cause) {
            super(cause);
        }
    }

    public static class Invalid extends Error {
        public Invalid(String msg) {
            super(msg);
        }
    }

    public static class Expired extends Error {

    }

    public static class BadID extends Error {
        public BadID(Throwable cause) {
            super(cause);
        }

        public BadID() {
            super();
        }
    }

    public static class BadSign extends Error {
        public BadSign() {
            super();
        }

        public BadSign(Throwable cause) {
            super(cause);
        }
    }

    static void runtimeCheck(boolean res, String message) {
        if (!res) {
            throw new RuntimeException(message);
        }
    }

    boolean verify(byte[] data, ECPublicKey pk, byte[] signature) throws CapBAC.BadID, CapBAC.BadSign {
        final Signature s;
        try {
            s = Signature.getInstance(ALG);
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
