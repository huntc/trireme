package com.apigee.noderunner.core.internal;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This is a class that maps between OpenSSL and Java ways of specifying Crypto algorithms. It tries to make
 * Java look as much like OpenSSL as possible because that's what this stuff expects.
 */

public class CryptoAlgorithms
{
    private static final CryptoAlgorithms myself = new CryptoAlgorithms();

    private static final String PADDING = "/PKCS5Padding";
    private static final String NO_PADDING = "/NoPadding";

    private final Pattern FULL_LENGTH = Pattern.compile("([A-Za-z0-9]+)-([0-9]+)-([A-Za-z0-9]+)");
    private final Pattern THREE_PARTS = Pattern.compile("([A-Za-z0-9]+)-([A-Za-z0-9]+)-([A-Za-z0-9]+)");
    private final Pattern TWO_PARTS = Pattern.compile("([A-Za-z0-9]+)-([A-Za-z0-9]+)");
    private final Pattern PIPE = Pattern.compile("|");

    private final HashMap<String, Spec> CIPHER_SPECS = new HashMap<String, Spec>();
    private final ArrayList<String> CIPHER_NAMES;

    public static CryptoAlgorithms get() {
        return myself;
    }

    private CryptoAlgorithms()
    {
        ArrayList<String> cipherNames = new ArrayList<String>();

        // Put together a list of all the providers
        for (Provider p : Security.getProviders()) {
            for(Provider.Service s : p.getServices()) {
                if ("Cipher".equals(s.getType())) {
                    String modes = s.getAttribute("SupportedModes");
                    if (modes != null) {
                        String algo = s.getAlgorithm().toLowerCase();
                        for (String mode : PIPE.split(modes)) {
                            cipherNames.add(algo + '-' + mode.toLowerCase());
                        }
                    }
                }
            }
        }

        // Only crypto algorithms that we can't handle normally
        CIPHER_SPECS.put("aes128", new Spec("AES/CBC/PKCS5Padding", "AES", 128));
        CIPHER_SPECS.put("aes192", new Spec("AES/CBC/PKCS5Padding", "AES", 192));
        CIPHER_SPECS.put("aes256", new Spec("AES/CBC/PKCS5Padding", "AES", 256));
        CIPHER_SPECS.put("bf", new Spec("Blowfish/CBC/PKCS5Padding", "Blowfish"));
        CIPHER_SPECS.put("blowfish", new Spec("Blowfish/CBC/PKCS5Padding", "Blowfish"));
        CIPHER_SPECS.put("des", new Spec("DES/CBC/PKCS5Padding", "DES"));
        CIPHER_SPECS.put("des3", new Spec("DESede/CBC/PKCS5Padding", "DES"));
        CIPHER_SPECS.put("des-ede", new Spec("DESede/CBC/PKCS5Padding", "DESede"));
        CIPHER_SPECS.put("rc2", new Spec("RC2/CBC/PKCS5Padding", "DESede"));
        CIPHER_SPECS.put("rc4", new Spec("RC4/CBC/PKCS5Padding", "DESede"));

        cipherNames.addAll(CIPHER_SPECS.keySet());
        Collections.sort(cipherNames);
        CIPHER_NAMES = cipherNames;
    }

    /**
     * Translate an OpenSSL algorithm like "aes-256-cbc" to a Java-compatible name like
     * "AES/CBC/PKCS5Padding".
     *
     * @param name the name as in OpenSSL, such as "aes-192-cbc"
     * @param padding if true, include padding as in PKCS5
     */
    public Spec getAlgorithm(String name, boolean padding)
    {
        String pad = padding ? PADDING : NO_PADDING;

        // First check special cases
        Spec spec = CIPHER_SPECS.get(name);
        if (spec == null) {
            Matcher m = FULL_LENGTH.matcher(name);
            if (m.matches()) {
                // This algorithm is something like "algo-length-mode"
                String algo = m.group(1);
                int len = Integer.parseInt(m.group(2));
                String mode = m.group(3);
                spec = new Spec(algo.toUpperCase() + '/' + mode.toUpperCase() + pad,
                                algo.toUpperCase(), len);

            } else {
                m = THREE_PARTS.matcher(name);
                if (m.matches()) {
                    // algo-more algo-mode, like "des-ede-cbc"
                    String algo = m.group(1);
                    String algo2 = m.group(2);
                    String mode = m.group(3);
                    String algoName = algo.toUpperCase() + algo2;
                    spec = new Spec(algoName + '/' + mode.toUpperCase() + pad,
                                    algoName);

                } else {
                    m = TWO_PARTS.matcher(name);
                    if (m.matches()) {
                        // algo-mode
                        String algo = m.group(1);
                        String mode = m.group(2);
                        spec = new Spec(algo.toUpperCase() + '/' + mode.toUpperCase() + pad,
                                       algo.toUpperCase());
                    }
                }
            }
        }

        if (spec != null) {
            spec.finish();
        }
        return spec;
    }

    public List<String> getCiphers()
    {
        return CIPHER_NAMES;
    }

    public static final class Spec
    {
        public static final int AES_IV_LEN = 16;

        private final String name;
        private final String algo;
        private final int keyLen;
        private int ivLen;

        Spec(String name, String algo, int keyLen)
        {
            this.name = name;
            this.algo = algo;
            this.keyLen = keyLen;
        }

        Spec(String name, String algo)
        {
            this.name = name;
            this.algo = algo;
            this.keyLen = 0;
        }

        void finish()
        {
            if ("AES".equals(algo)) {
                ivLen = AES_IV_LEN;
            }
        }

        public String getName()
        {
            return name;
        }

        public String getAlgo()
        {
            return algo;
        }

        public int getKeyLen()
        {
            return keyLen;
        }

        public int getIvLen()
        {
            return ivLen;
        }

        public void setIvLen(int ivLen)
        {
            this.ivLen = ivLen;
        }
    }
}
