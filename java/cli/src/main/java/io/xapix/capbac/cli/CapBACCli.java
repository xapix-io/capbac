package io.xapix.capbac.cli;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.converters.FileConverter;
import com.beust.jcommander.converters.URLConverter;
import com.google.protobuf.util.JsonFormat;
import io.xapix.capbac.*;
import io.xapix.capbac.keypairs.StaticMapKeypairs;
import io.xapix.capbac.resolvers.StaticMapResolver;
import io.xapix.capbac.trust.PatternChecker;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Pattern;

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

    static class HolderArgs {
        @Parameter(names = "--me", description = "ID of holder", required = true, converter = URLConverter.class)
        URL me;

        @Parameter(names = "--sk", description = "Private key path", required = true, converter = FileConverter.class)
        File sk;
    }

    static class IDMaping {

        static class Converter implements IStringConverter<IDMaping> {
            @Override
            public IDMaping convert(String value) {
                try {
                    String[] parts = value.split("=");

                    return new IDMaping(new URL(parts[0]), readFileToByteArray(new File(parts[1])));
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }

        final URL id;
        final byte[] pk;

        public IDMaping(URL id, byte[] pk) {
            this.id = id;
            this.pk = pk;
        }
    }

    static class ResolverArgs {
        @Parameter(names = "--id", description = "ID to public key map", converter = IDMaping.Converter.class)
        List<IDMaping> ids = new ArrayList<>();
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

        @Parameter(names = "--cert", description = "Certificates for invocation", converter = FileConverter.class)
        List<File> certs;

        @Parameter(names = "--exp", description = "Expiration time")
        long exp = 0;
    }

    static class ValidateArgs {
        @Parameter(names = "--trust-ids", description = "Regexp to check that id is trusted. By default everything is valid", converter = PatternConverter.class)
        Pattern trustRegex = Pattern.compile(".*");

        @Parameter(names = "--now", description = "Current time in seconds regarding expiration validation. By default is system time")
        long now = new Date().toInstant().toEpochMilli() / 1000;
    }

    private ValidateArgs validateArgs = new ValidateArgs();
    private HolderArgs holderArgs = new HolderArgs();
    private ResolverArgs resolverArgs = new ResolverArgs();
    private CertificateArgs certArgs = new CertificateArgs();
    private InvokeArgs invokeArgs = new InvokeArgs();

    private void run(String[] argv) {
        Security.addProvider(new BouncyCastleProvider());

        JCommander jc = JCommander.newBuilder()
                .addCommand("forge", new Object[] { holderArgs, resolverArgs , certArgs })
                .addCommand("delegate", new Object[] { holderArgs, resolverArgs , certArgs })
                .addCommand("invoke", new Object[] { holderArgs, resolverArgs , invokeArgs })
                .addCommand("certificate", new Object())
                .addCommand("certificate-validate", new Object[] { validateArgs })
                .addCommand("invocation", new Object())
                .addCommand("invocation-validate", new Object[] { validateArgs })
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
                    cert.validate(makeCapBAC(), new PatternChecker(validateArgs.trustRegex), validateArgs.now);
                    break;
                case "invocation":
                    printInvocation();
                    break;
                case "invocation-validate":
                    CapBACInvocation inv = printInvocation();
                    inv.validate(makeCapBAC(), new PatternChecker(validateArgs.trustRegex), validateArgs.now);
                    break;
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (CapBAC.Malformed malformed) {
            System.err.println("Malformed data");
            malformed.getCause().printStackTrace();
            System.exit(11);
        } catch (CapBAC.BadID badID) {
            System.err.println("Bad ID");
            System.exit(12);
        } catch (CapBAC.Invalid invalid) {
            System.err.println("Invalid data");
            System.exit(13);
        } catch (CapBAC.Expired expired) {
            System.err.println("Expired certificate");
            System.exit(14);
        } catch (CapBAC.BadSign badSign) {
            System.err.println("Bad sign");
            System.exit(15);
        }
    }

    private void runForge() throws CapBAC.BadID {
        try {
            CapBACHolder holder = makeHolder();
            CapBACCertificate.Builder builder = makeCertBuilder();
            CapBACCertificate.Raw res = holder.forge(builder);
            System.out.write(res.encode());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void runInvoke() throws CapBAC.BadID, CapBAC.Malformed {
        try {
            CapBACHolder holder = makeHolder();
            CapBACInvocation.Builder builder = makeInvokeBuilder();
            CapBACInvocation.Raw res = holder.invoke(builder);
            System.out.write(res.encode());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void runDelegate() throws IOException, CapBAC.BadID, CapBAC.Malformed {
        byte[] input = IOUtils.toByteArray(System.in);
        CapBACHolder holder = makeHolder();
        CapBACCertificate.Builder builder = makeCertBuilder();
        CapBACCertificate.Raw res = holder.delegate(new CapBACCertificate.Raw(input), builder);
        System.out.write(res.encode());
    }

    private CapBACCertificate.Builder makeCertBuilder() {
        return new CapBACCertificate.Builder(certArgs.subject, certArgs.capability.getBytes())
                .withExp(certArgs.exp);
    }

    private CapBACInvocation.Builder makeInvokeBuilder() throws CapBAC.Malformed {
        try {
            CapBACInvocation.Builder builder = new CapBACInvocation.Builder(invokeArgs.action.getBytes())
                    .withExp(certArgs.exp);

            for (File cert : invokeArgs.certs) {
                builder.addCert(new CapBACCertificate.Raw(readFileToByteArray(cert)));
            }
            return builder;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private CapBAC makeCapBAC() {
        HashMap<URL, byte[]> idMap = new HashMap<>();
        for (IDMaping id : resolverArgs.ids) {
            idMap.put(id.id, id.pk);
        }
        StaticMapResolver resolver = new StaticMapResolver(idMap);
        return new CapBAC(resolver);
    }

    private CapBACHolder makeHolder() {
        try {
            byte[] sk = readFileToByteArray(holderArgs.sk);
            CapBAC capBAC = makeCapBAC();
            HashMap<URL, ECPrivateKey> keypairsMap = new HashMap<>();
            keypairsMap.put(holderArgs.me, bytesToSK(sk));

            return new CapBACHolder(holderArgs.me, capBAC, new StaticMapKeypairs(keypairsMap));

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] argv) {
        new CapBACCli().run(argv);
    }


    private static CapBACCertificate printCertificate() throws CapBAC.Malformed {
        byte[] bytes = new byte[0];
        try {
            bytes = IOUtils.toByteArray(System.in);
        } catch (IOException e) {
            throw new CapBAC.Malformed(e);
        }
        return printCertificate(new CapBACCertificate.Raw(bytes));
    }

    private static CapBACCertificate printCertificate(CapBACCertificate.Raw rawCert) throws CapBAC.Malformed {
        CapBACCertificate rootCert = rawCert.parse();
        CapBACCertificate cert = rootCert;
        try {
            while (cert != null) {
                CapBACProto.Certificate.Payload payload = null;
                payload = CapBACProto.Certificate.Payload.parseFrom(cert.getRaw().proto.getPayload());

                System.out.println(JsonFormat.printer().print(cert.getRaw().proto));

                System.out.println(JsonFormat.printer().print(payload));

                cert = cert.getParent();
            }
        }
        catch (IOException e) {
            throw new CapBAC.Malformed(e);
        }
        return rootCert;
    }

    private static CapBACInvocation printInvocation() throws CapBAC.Malformed {
        try {
            byte[] bytes = IOUtils.toByteArray(System.in);
            CapBACInvocation inv = new CapBACInvocation.Raw(bytes).parse();
            System.out.println(JsonFormat.printer().print(inv.getRaw().proto));

            CapBACProto.Invocation.Payload payload = CapBACProto.Invocation.Payload.parseFrom(inv.getRaw().proto.getPayload());
            System.out.println(JsonFormat.printer().print(payload));
            for (CapBACCertificate.Raw cert : inv.getCertificates()) {
                printCertificate(cert);
            }

            return inv;
        }
        catch (IOException e) {
            throw new CapBAC.Malformed(e);
        }
    }


    private static ECPrivateKey bytesToSK(byte[] keyBytes) {
        PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(keyBytes)));
        PEMKeyPair pemKeyPair = null;
        try {
            pemKeyPair = (PEMKeyPair)pemParser.readObject();


            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            KeyPair keyPair = converter.getKeyPair(pemKeyPair);
            pemParser.close();

            return (ECPrivateKey)keyPair.getPrivate();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
