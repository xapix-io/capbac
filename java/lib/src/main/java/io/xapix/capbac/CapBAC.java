package io.xapix.capbac;

import java.net.URL;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class CapBAC {
    String ALG = "SHA256withECDSA";
    String KEYS = "KEYS";
    CapBACResolver resolver;

    public CapBAC(CapBACResolver resolver) {
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

    ECPublicKey bytesToPK(byte[] keyBytes) throws CapBAC.BadID {
        try {
            KeyFactory kf = KeyFactory.getInstance(KEYS);
            EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            return (ECPublicKey) kf.generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new CapBAC.BadID(e);
        } catch (NoSuchAlgorithmException e) {
            throw new CapBAC.SignatureError(e);
        }
    }

    boolean verify(byte[] data, byte[] pk, byte[] signature) throws CapBAC.BadID, CapBAC.BadSign {
        final Signature s;
        try {
            s = Signature.getInstance(ALG);
            s.initVerify(bytesToPK(pk));
            s.update(data);
            return s.verify(signature);
        } catch (NoSuchAlgorithmException e) {
            throw new CapBAC.SignatureError(e);
        } catch (SignatureException | InvalidKeyException e) {
            throw new CapBAC.BadSign(e);
        }
    }
}
