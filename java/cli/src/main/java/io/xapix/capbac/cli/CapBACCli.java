package io.xapix.capbac.cli;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.converters.FileConverter;
import com.beust.jcommander.converters.URLConverter;
import com.google.protobuf.util.JsonFormat;
import io.xapix.capbac.CapBAC;
import io.xapix.capbac.CapBACCertificate;
import io.xapix.capbac.CapBACHolder;
import io.xapix.capbac.CapBACKeypair;
import io.xapix.capbac.resolvers.StaticMapResolver;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static org.apache.commons.io.FileUtils.readFileToByteArray;

public class CapBACCli {

    static class UrlConverter implements IStringConverter<URL> {
        @Override
        public URL convert(String value) {
            try {
                return new URL(value);
            } catch (MalformedURLException e) {
                throw new RuntimeException(e);
            }
        }
    }

    static class HolderArgs {
        @Parameter(names = "--me", description = "ID of holder", required = true, converter = URLConverter.class)
        URL me;

        @Parameter(names = "--pk", description = "Public key path", required = true, converter = FileConverter.class)
        File pk;

        @Parameter(names = "--sk", description = "Private key path", required = true, converter = FileConverter.class)
        File sk;
    }

    static class ResolverArgs {
        @Parameter(names = "-debug", description = "Debug mode", required = true)
        private boolean debug = false;
    }

    static class CertificateArgs {
        @Parameter(names = "--capability", description = "Capability", required = true)
        String capability;

        @Parameter(names = "--exp", description = "Expiration time")
        long exp = 0;

        @Parameter(names = "--subject", description = "Target subject", required = true, converter = URLConverter.class)
        URL subject;
    }

    public static void main(String[] argv) throws IOException, CapBAC.BadID {
        HolderArgs holderArgs = new HolderArgs();
        CertificateArgs certArgs = new CertificateArgs();
//        CommandForge resolver = new CommandForge();
        JCommander jc = JCommander.newBuilder()
                .addCommand("forge", new Object[] { holderArgs , certArgs })
                .build();
        jc.parse(argv);

        if(jc.getParsedCommand() == null) {
            jc.usage();
            System.exit(1);
        }

        switch(jc.getParsedCommand()) {
            case "forge":
                byte[] pk = readFileToByteArray(holderArgs.pk);
                byte[] sk = readFileToByteArray(holderArgs.sk);
                HashMap<URL, byte[]> idMap = new HashMap<>();
                idMap.put(holderArgs.me, pk);
                StaticMapResolver resolver = new StaticMapResolver(idMap);
                CapBAC capBAC = new CapBAC(resolver);
                CapBACKeypair keypair = new CapBACKeypair(bytesToPK(pk), bytesToSK(sk));
                CapBACHolder holder = new CapBACHolder(holderArgs.me, capBAC, keypair);
                CapBACCertificate.Builder builder = new CapBACCertificate.Builder(certArgs.subject, certArgs.capability.getBytes())
                        .withExp(certArgs.exp);
                CapBACCertificate.Raw res = holder.forge(builder);
                System.out.println(JsonFormat.printer().print(res.proto));
                break;
        }
    }

    private static ECPublicKey bytesToPK(byte[] keyBytes) throws CapBAC.BadID {
        try {
            KeyFactory kf = KeyFactory.getInstance("SHA256withECDSA");
            EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            return (ECPublicKey) kf.generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new CapBAC.BadID(e);
        } catch (NoSuchAlgorithmException e) {
            throw new CapBAC.SignatureError(e);
        }
    }

    private static ECPrivateKey bytesToSK(byte[] keyBytes) throws CapBAC.BadID {
        try {
            KeyFactory kf = KeyFactory.getInstance("SHA256withECDSA");
            EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            return (ECPrivateKey) kf.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new CapBAC.BadID(e);
        } catch (NoSuchAlgorithmException e) {
            throw new CapBAC.SignatureError(e);
        }
    }
}
