package io.xapix.capbac.cli;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.converters.FileConverter;
import com.beust.jcommander.converters.URLConverter;
import com.google.protobuf.util.JsonFormat;
import io.xapix.capbac.*;
import io.xapix.capbac.trust.PatternChecker;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Pattern;

import static org.apache.commons.io.FileUtils.readFileToString;
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

    static class PatternConverter implements IStringConverter<Pattern> {
        @Override
        public Pattern convert(String value) {
            return Pattern.compile(value);
        }
    }

    abstract static class IDMapping<T> {
        final URL id;
        final T val;
        public IDMapping(String val) {
            try {
                String[] parts = val.split("=");
                this.id = new URL(parts[0]);
                this.val = parse(readFileToByteArray(new File(parts[1])));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        abstract T parse(byte[] content);
    }

    static class PKMapping extends IDMapping<ECPublicKey>  {
        PKMapping(String val) {
            super(val);
        }

        static class Converter implements IStringConverter<PKMapping> {
            @Override
            public PKMapping convert(String value) {
                return new PKMapping(value);
            }
        }

        private byte[] parsePEM(Reader pem) throws IOException {
            PemReader reader = new PemReader(pem);
            PemObject pemObject = reader.readPemObject();
            byte[] content = pemObject.getContent();
            reader.close();
            return content;
        }

        @Override
        public ECPublicKey parse(byte[] content) {
            try {
                KeyFactory kf = KeyFactory.getInstance("EC");
                EncodedKeySpec keySpec = new X509EncodedKeySpec(parsePEM(new StringReader(new String(content))));
                return (ECPublicKey) kf.generatePublic(keySpec);
            } catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException e) {
                throw new RuntimeException(e);
            }
        }
    }


    static class HolderArgs {
        @Parameter(names = "--me", description = "ID of holder", required = true, converter = URLConverter.class)
        URL me;
        @Parameter(names = "--sk", description = "Private key", converter = HolderArgs.Converter.class)
        ECPrivateKey sk;

        static class Converter implements IStringConverter<ECPrivateKey> {
            @Override
            public ECPrivateKey convert(String path) {
                try {
                    String content = readFileToString(new File(path), StandardCharsets.UTF_8);
                    PEMParser pemParser = new PEMParser(new StringReader(content));
                    PEMKeyPair pemKeyPair;
                    pemKeyPair = (PEMKeyPair)pemParser.readObject();

                    JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                    KeyPair keyPair = converter.getKeyPair(pemKeyPair);
                    pemParser.close();

                    return (ECPrivateKey) keyPair.getPrivate();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }

    static class PubsArgs implements CapBACPubs {
        @Parameter(names = "--pub", description = "ID to public key map", converter = PKMapping.Converter.class)
        List<PKMapping> ids = new ArrayList<>();

        @Override
        public ECPublicKey get(URL id) {
            for (PKMapping mapping : ids) {
                if (mapping.id.equals(id)) {
                    return mapping.val;
                }
            }
            return null;
        }
    }

    static class CertificateArgs {
        @Parameter(names = "--capability", description = "Capability", required = true)
        String capability;

        @Parameter(names = "--exp", description = "Expiration time")
        long exp = 0;

        @Parameter(names = "--subject", description = "Target subject", required = true, converter = URLConverter.class)
        URL subject;
    }

    static class InvokeArgs {
        @Parameter(names = "--action", description = "Action", required = true)
        String action;

        @Parameter(names = "--cert", description = "Certificate for invocation", required = true, converter = FileConverter.class)
        File cert;

        @Parameter(names = "--exp", description = "Expiration time")
        long exp = 0;
    }

    static class ValidateArgs {
        @Parameter(names = "--trust-ids", description = "Regexp to check that id is trusted. By default everything is valid", converter = PatternConverter.class)
        Pattern trustRegex = Pattern.compile(".*");

        @Parameter(names = "--now", description = "Current time in seconds regarding expiration validation. By default is system time")
        long now = new Date().toInstant().toEpochMilli() / 1000;
    }

    private final ValidateArgs validateArgs = new ValidateArgs();
    private final HolderArgs holderArgs = new HolderArgs();
    private final PubsArgs pubs = new PubsArgs();
    private final CertificateArgs certArgs = new CertificateArgs();
    private final InvokeArgs invokeArgs = new InvokeArgs();

    private void run(String[] argv) {
        Security.addProvider(new BouncyCastleProvider());

        JCommander jc = JCommander.newBuilder()
                .addCommand("forge", new Object[] { holderArgs, certArgs })
                .addCommand("delegate", new Object[] { holderArgs, certArgs })
                .addCommand("invoke", new Object[] { holderArgs, invokeArgs })
                .addCommand("certificate", new Object())
                .addCommand("certificate-validate", new Object[] { validateArgs, pubs })
                .addCommand("invocation", new Object())
                .addCommand("invocation-validate", new Object[] { validateArgs, pubs })
                .build();
        jc.parse(argv);

        if(jc.getParsedCommand() == null) {
            jc.usage();
            System.exit(1);
        }

        try {
            switch(jc.getParsedCommand()) {
                case "forge":
                    runForge();
                    break;
                case "delegate":
                    runDelegate();
                    break;
                case "invoke":
                    runInvoke();
                    break;
                case "certificate":
                    printCertificate();
                    break;
                case "certificate-validate":
                    CapBACCertificate cert = printCertificate();
                    new CapBACValidator(new PatternChecker(validateArgs.trustRegex), pubs).validate(cert, validateArgs.now);
                    break;
                case "invocation":
                    printInvocation();
                    break;
                case "invocation-validate":
                    CapBACInvocation inv = printInvocation();
                    new CapBACValidator(new PatternChecker(validateArgs.trustRegex), pubs).validate(inv, validateArgs.now);
                    break;
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (CapBAC.Malformed e) {
            System.err.println(e.toString());
            System.exit(11);
        } catch (CapBAC.BadID e) {
            System.err.println(e.toString());
            System.exit(12);
        } catch (CapBAC.Invalid e) {
            System.err.println(e.toString());
            System.exit(13);
        } catch (CapBAC.Expired e) {
            System.err.println(e.toString());
            System.exit(14);
        } catch (CapBAC.BadSign e) {
            System.err.println(e.toString());
            System.exit(15);
        }
    }

    private void runForge() throws CapBAC.BadID {
        try {
            CapBACHolder holder = makeHolder();
            CapBACCertificate.Builder builder = makeCertBuilder();
            CapBACCertificate res = holder.forge(builder);
            System.out.write(res.encode());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void runInvoke() throws CapBAC.Malformed {
        try {
            CapBACHolder holder = makeHolder();
            CapBACInvocation.Builder builder = makeInvokeBuilder();
            CapBACInvocation res = holder.invoke(builder);
            System.out.write(res.encode());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void runDelegate() throws IOException, CapBAC.Malformed {
        byte[] input = IOUtils.toByteArray(System.in);
        CapBACHolder holder = makeHolder();
        CapBACCertificate.Builder builder = makeCertBuilder();
        CapBACCertificate res = holder.delegate(new CapBACCertificate(input), builder);
        System.out.write(res.encode());
    }

    private CapBACCertificate.Builder makeCertBuilder() {
        return new CapBACCertificate.Builder(certArgs.subject, certArgs.capability.getBytes())
                .withExp(certArgs.exp);
    }

    private CapBACInvocation.Builder makeInvokeBuilder() throws CapBAC.Malformed {
        try {
            return new CapBACInvocation.Builder(
                    new CapBACCertificate(readFileToByteArray(invokeArgs.cert)), invokeArgs.action.getBytes())
                    .withExp(invokeArgs.exp);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private CapBACHolder makeHolder() {
        return new CapBACHolder(holderArgs.me, holderArgs.sk);
    }

    public static void main(String[] argv) {
        new CapBACCli().run(argv);
    }


    private static CapBACCertificate printCertificate() throws CapBAC.Malformed {
        byte[] bytes;
        try {
            bytes = IOUtils.toByteArray(System.in);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return printCertificate(new CapBACCertificate(bytes));
    }

    private static CapBACCertificate printCertificate(CapBACCertificate rootCert){
        CapBACCertificate cert = rootCert;
        try {
            while (cert != null) {
                CapBACProto.Certificate.Payload payload;
                payload = CapBACProto.Certificate.Payload.parseFrom(cert.getProto().getPayload());

                System.out.println(JsonFormat.printer().print(cert.getProto()));

                System.out.println(JsonFormat.printer().print(payload));

                cert = cert.getParent();
            }
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
        return rootCert;
    }

    private static CapBACInvocation printInvocation() throws CapBAC.Malformed {
        try {
            byte[] bytes = IOUtils.toByteArray(System.in);
            CapBACInvocation inv = new CapBACInvocation(bytes);
            System.out.println(JsonFormat.printer().print(inv.getProto()));

            CapBACProto.Invocation.Payload payload = CapBACProto.Invocation.Payload.parseFrom(inv.getProto().getPayload());
            System.out.println(JsonFormat.printer().print(payload));
            printCertificate(inv.getCertificate());

            return inv;
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
