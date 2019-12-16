package io.xapix.capbac;

import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

class CapBAC {
    String ALG = "SHA256withECDSA";
    CapBACResolver resolver;

    public CapBAC(CapBACResolver resolver) {
        this.resolver = resolver;
    }

    static class SignatureError extends RuntimeException{
        SignatureError(Throwable cause) {
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
            KeyFactory kf = KeyFactory.getInstance(ALG);
            EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            return (ECPublicKey) kf.generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new CapBAC.BadID(e);
        } catch (NoSuchAlgorithmException e) {
            throw new CapBAC.SignatureError(e);
        }
    }
}
