package com.apigee.noderunner.core.modules;

import com.apigee.noderunner.core.internal.Charsets;
import com.apigee.noderunner.core.internal.CryptoAlgorithms;
import com.apigee.noderunner.core.internal.InternalNodeModule;
import com.apigee.noderunner.core.internal.Utils;
import com.apigee.noderunner.core.NodeRuntime;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.EvaluatorException;
import org.mozilla.javascript.Function;
import org.mozilla.javascript.FunctionObject;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.ScriptableObject;
import org.mozilla.javascript.Undefined;
import org.mozilla.javascript.annotations.JSConstructor;
import org.mozilla.javascript.annotations.JSFunction;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Random;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.apigee.noderunner.core.internal.ArgUtils.*;

public class Crypto
    implements InternalNodeModule
{
    public static final String MODULE_NAME = "crypto";

    /** This is a maximum value for a byte buffer that seems to be part of V8. Used to make tests pass. */
    public static final long MAX_BUFFER_LEN = 0x3fffffffL;

    @Override
    public String getModuleName()
    {
        return MODULE_NAME;
    }

    @Override
    public Scriptable registerExports(Context cx, Scriptable scope, NodeRuntime runtime)
        throws InvocationTargetException, IllegalAccessException, InstantiationException
    {
        ScriptableObject.defineClass(scope, CryptoImpl.class);
        CryptoImpl export = (CryptoImpl) cx.newObject(scope, CryptoImpl.CLASS_NAME);
        export.setRuntime(runtime);

        // We have to lock the scope in which the randomBytes/pseudoRandomBytes methods are executed to the `export`
        // CryptoImpl instance. In the JS module, the binding methods are exposed through exports, but this reassignment
        // makes them lose the scope of the module. That is:
        //
        //      var binding = process.binding('crypto');
        //
        //      binding.randomBytes(...);           // works fine
        //
        //      var r = binding.randomBytes;
        //      r();                                // fails; wrong scope
        //
        // These methods can't be static/independent of the module because we need access to the runtime.
        //
        // Interestingly enough, when using the "regular," non-varargs version of JSFunction, Rhino pulls a new instance
        // of CryptoImpl out of a hat and uses it for the `this` scope in the Java code. This new instance is
        // *not* `exports`, and hasn't been initialized here, so it doesn't have a reference to the runtime.
        // With the varargs form, `thisObj` is the "wrong" scope (not a CryptoImpl), and func.getParentScope()
        // is the new, uninitialized CryptoImpl instance.
        ScriptableObject proto = (ScriptableObject) export.getPrototype();
        FunctionObject randomBytes = (FunctionObject) proto.get("randomBytes", proto);
        randomBytes.setParentScope(export);
        FunctionObject pseudoRandomBytes = (FunctionObject) proto.get("pseudoRandomBytes", proto);
        pseudoRandomBytes.setParentScope(export);

        ScriptableObject.defineClass(export, HashImpl.class, false, true);
        ScriptableObject.defineClass(export, MacImpl.class, false, true);
        ScriptableObject.defineClass(export, SecureContextImpl.class, false, false);
        ScriptableObject.defineClass(export, SignImpl.class, false, false);
        ScriptableObject.defineClass(export, CipherImpl.class, false, false);
        ScriptableObject.defineClass(export, DecipherImpl.class, false, false);

        return export;
    }

    public static class CryptoImpl
        extends ScriptableObject
    {
        public static final String CLASS_NAME = "_cryptoClass";

        private static final SecureRandom secureRandom = new SecureRandom();
        private static final Random pseudoRandom = new Random();

        private NodeRuntime runtime;

        // TODO: SecureContext
        // TODO: Hmac
        // TODO: Cipher
        // TODO: Decipher
        // TODO: Sign
        // TODO: Verify
        // TODO: DiffieHellman
        // TODO: DiffieHellmanGroup
        // TODO: PBKDF2

        @Override
        public String getClassName()
        {
            return CLASS_NAME;
        }

        @JSFunction
        public static Object randomBytes(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            return randomBytesCommon(cx, thisObj, args, func, secureRandom);
        }

        @JSFunction
        public static Object pseudoRandomBytes(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            return randomBytesCommon(cx, thisObj, args, func, pseudoRandom);
        }

        private static Object randomBytesCommon(Context cx, Scriptable thisObj, Object[] args, Function func, Random randomImpl) {
            CryptoImpl thisClass = (CryptoImpl) func.getParentScope();

            // the tests are picky about what can be passed in as size -- only a valid number
            Number sizeNum = objArg(args, 0, Number.class, false);

            // TypeErrors are thrown on call, not returned in callback
            if (sizeNum == null) {
                throw Utils.makeTypeError(cx, thisObj, "size must be a number");
            } else {
                if (sizeNum.longValue() < 0) {
                    throw Utils.makeTypeError(cx, thisObj, "size must be >= 0");
                } else if (sizeNum.longValue() > MAX_BUFFER_LEN) {
                    throw Utils.makeTypeError(cx, thisObj, "size must be a valid integer");
                }
            }

            Function callback = objArg(args, 1, Function.class, false);

            byte[] randomBytes = new byte[sizeNum.intValue()];
            randomImpl.nextBytes(randomBytes);
            Buffer.BufferImpl randomBytesBuffer = Buffer.BufferImpl.newBuffer(cx, thisObj, randomBytes);

            if (callback != null) {
                // TODO: what exception can be returned here?
                thisClass.runtime.enqueueCallback(callback, callback, thisObj, thisClass.runtime.getDomain(),
                        new Object[] { null, randomBytesBuffer });
                return Undefined.instance;
            } else {
                return randomBytesBuffer;
            }
        }

        @JSFunction
        public static Scriptable getCiphers(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            // TODO: getCiphers
            throw new EvaluatorException("Not implemented");
        }

        @JSFunction
        public static Scriptable getHashes(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            return cx.newArray(thisObj, HashImpl.SUPPORTED_ALGORITHMS.toArray());
        }

        private void setRuntime(NodeRuntime runtime) {
            this.runtime = runtime;
        }
    }

    public static class HashImpl
        extends ScriptableObject
    {
        public static final String CLASS_NAME = "Hash";

        public static final HashMap<String, String> MD_ALGORITHMS = new HashMap<String, String>();
        static {
            MD_ALGORITHMS.put("md2", "MD2");
            MD_ALGORITHMS.put("md5", "MD5");
            MD_ALGORITHMS.put("sha1", "SHA-1");
            MD_ALGORITHMS.put("sha256", "SHA-256");
            MD_ALGORITHMS.put("sha384", "SHA-384");
            MD_ALGORITHMS.put("sha512", "SHA-512");
        }
        public static final Set<String> SUPPORTED_ALGORITHMS = MD_ALGORITHMS.keySet();

        private MessageDigest messageDigest;

        @Override
        public String getClassName()
        {
            return CLASS_NAME;
        }

        @JSConstructor
        public static Object hashConstructor(Context cx, Object[] args, Function ctorObj, boolean inNewExpr)
        {
            HashImpl ret;
            if (inNewExpr) {
                ret = new HashImpl();
            } else {
                ret = (HashImpl) cx.newObject(ctorObj, CLASS_NAME);
            }
            ret.initializeHash(cx, args, ctorObj);
            return ret;
        }

        private void initializeHash(Context cx, Object[] args, Function ctorObj)
        {
            String nodeAlgorithm = stringArg(args, 0);

            String jceAlgorithm = MD_ALGORITHMS.get(nodeAlgorithm);
            if (jceAlgorithm == null) {
                jceAlgorithm = nodeAlgorithm;
            }

            try {
                messageDigest = MessageDigest.getInstance(jceAlgorithm);
            } catch (NoSuchAlgorithmException e) {
                throw Utils.makeError(cx, ctorObj, "Digest method not supported");
            }
        }

        @JSFunction
        public static void update(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            HashImpl thisClass = (HashImpl) thisObj;
            ensureArg(args, 0);
            String encoding = stringArg(args, 1, null);

            if (args[0] instanceof String) {
                ByteBuffer bb = Utils.stringToBuffer(stringArg(args, 0),
                                                     Charsets.get().resolveCharset(encoding));
                thisClass.messageDigest.update(bb.array(), bb.arrayOffset(), bb.limit());
            } else {
                Buffer.BufferImpl buf = objArg(args, 0, Buffer.BufferImpl.class, true);
                thisClass.messageDigest.update(buf.getArray(), buf.getArrayOffset(), buf.getLength());
            }
        }

        @JSFunction
        public static Object digest(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            HashImpl thisClass = (HashImpl) thisObj;
            String encoding = stringArg(args, 0, null);

            byte[] digest = thisClass.messageDigest.digest();
            if ((encoding == null) || "buffer".equals(encoding)) {
                return Buffer.BufferImpl.newBuffer(cx, thisObj, digest);
            }
            ByteBuffer bb = ByteBuffer.wrap(digest);
            return Utils.bufferToString(bb, Charsets.get().resolveCharset(encoding));
        }

    }

    public static class MacImpl
        extends ScriptableObject
    {
        public static final String CLASS_NAME = "Hmac";

        public static final HashMap<String, String> MAC_ALGORITHMS = new HashMap<String, String>();
        static {
            MAC_ALGORITHMS.put("md5", "HmacMD5");
            MAC_ALGORITHMS.put("sha1", "HmacSHA1");
            MAC_ALGORITHMS.put("sha256", "HmacSHA256");
            MAC_ALGORITHMS.put("sha384", "HmacSHA384");
            MAC_ALGORITHMS.put("sha512", "HmacSHA512");
        }

        private Mac digest;

        @Override
        public String getClassName()
        {
            return CLASS_NAME;
        }

        @JSFunction
        public static void init(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            String nodeAlgorithm = stringArg(args, 0);
            Buffer.BufferImpl buf = objArg(args, 1, Buffer.BufferImpl.class, true);
            MacImpl self = (MacImpl)thisObj;

            String jceAlgorithm = MAC_ALGORITHMS.get(nodeAlgorithm);
            if (jceAlgorithm == null) {
                jceAlgorithm = nodeAlgorithm;
            }

            try {
                self.digest = Mac.getInstance(jceAlgorithm);
            } catch (NoSuchAlgorithmException e) {
                throw Utils.makeError(cx, thisObj, "Digest method not supported: \"" + jceAlgorithm + '\"');
            }

            if ((buf != null) && (buf.getLength() > 0)) {
                SecretKeySpec key = new SecretKeySpec(buf.getArray(), buf.getArrayOffset(),
                                                      buf.getLength(), jceAlgorithm);
                try {
                    self.digest.init(key);
                } catch (InvalidKeyException e) {
                    throw Utils.makeError(cx, thisObj, "Error initializing key: " + e);
                }
            }
        }

        @JSFunction
        public static void update(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            MacImpl thisClass = (MacImpl) thisObj;
            ensureArg(args, 0);
            String encoding = stringArg(args, 1, null);

            if (args[0] instanceof String) {
                ByteBuffer bb = Utils.stringToBuffer(stringArg(args, 0),
                                                     Charsets.get().resolveCharset(encoding));
                thisClass.digest.update(bb.array(), bb.arrayOffset(), bb.limit());
            } else {
                Buffer.BufferImpl buf = objArg(args, 0, Buffer.BufferImpl.class, true);
                thisClass.digest.update(buf.getArray(), buf.getArrayOffset(), buf.getLength());
            }
        }

        @JSFunction
        public static Object digest(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            MacImpl thisClass = (MacImpl) thisObj;
            String encoding = stringArg(args, 0, null);

            byte[] digest = thisClass.digest.doFinal();
            if ((encoding == null) || "buffer".equals(encoding)) {
                return Buffer.BufferImpl.newBuffer(cx, thisObj, digest);
            }
            ByteBuffer bb = ByteBuffer.wrap(digest);
            return Utils.bufferToString(bb, Charsets.get().resolveCharset(encoding));
        }
    }

    public abstract static class AbstractCipherImpl
        extends ScriptableObject
    {
        private static final byte[] EMPTY_BUF = new byte[0];

        private Cipher cipher;
        private byte[] pwBuf;
        private String cipherName;
        private boolean padding = true;
        private boolean initialized;

        protected abstract int getMode();

        protected static void setAutoPaddingInternal(Context cx, Scriptable thisObj, Object[] args)
        {
            AbstractCipherImpl self = (AbstractCipherImpl)thisObj;

            if (self.initialized) {
                throw Utils.makeError(cx, thisObj, "Cannot call setAutoPadding after update or final");
            }
            self.padding = booleanArg(args, 0, true);
        }

        protected static void initInternal(Context cx, Scriptable thisObj, Object[] args)
        {
            AbstractCipherImpl self = (AbstractCipherImpl)thisObj;
            self.cipherName = stringArg(args, 0);
            Buffer.BufferImpl pw = objArg(args, 1, Buffer.BufferImpl.class, true);

            // Copy the password so that the buffer can get GCed and we can clear it when done
            self.pwBuf = new byte[pw.getLength()];
            System.arraycopy(pw.getArray(), pw.getArrayOffset(), self.pwBuf, 0, pw.getLength());
        }


        private void initialize(Context cx)
        {
            /*
             * Aargh. To do this, we will need to somehow:
             *
             * . Figure out if the algorithm requires an IV, and if so, which size
             * . If so, then generate the random IV during encryption
             * . On the first "update," or "final" if not, return the IV as a prefix to the ciphertext
             * . Then on decryption, on the first "update" or "final," read the IV bytes first
             * . Don't forget that you might not get all, say, 16 bytes on the first call, so save state
             * . Then use the IV to initialize decryption
             * . Then decrypt
             * . and remember that we might only need this rigamarole for AES
             */
            CryptoAlgorithms.Spec algSpec = CryptoAlgorithms.get().getAlgorithm(cipherName, padding);
            if (algSpec == null) {
                throw Utils.makeError(cx, this, "Unsupported cipher algorithm " + cipher);
            }

            try {
                cipher = Cipher.getInstance(algSpec.getName());
            } catch (GeneralSecurityException gse) {
                throw Utils.makeError(cx, this, "Cipher algorithm " + cipherName + " (" +
                                      algSpec.getName() + ") unsupported on the JVM");
            }

            Key key;

            try {
                if (algSpec.getKeyLen() > 0) {
                    // Some crypto algorithms require that the key be set to a specific length. So we need to hash the
                    // password and use it to generate a key of the exact length required.
                    // Regular node does this using an OpenSSL method that uses MD5 with no salt,
                    // so that's what we use.
                    byte[] digest;
                    try {
                        MessageDigest digester = MessageDigest.getInstance("MD5");
                        digester.update(pwBuf);
                        digest = digester.digest();
                    } catch (GeneralSecurityException gse) {
                        throw Utils.makeError(cx, this, "Error digesting cipher key: " + gse);
                    }

                    int desiredLen = Math.min(digest.length, algSpec.getKeyLen() / 8);
                    key = new SecretKeySpec(digest, 0, desiredLen, algSpec.getAlgo());

                } else {
                    key = new SecretKeySpec(pwBuf, algSpec.getAlgo());
                }
            } finally {
                Arrays.fill(pwBuf, (byte)0);
            }

            try {
                cipher.init(getMode(), key);
            } catch (GeneralSecurityException gse) {
                throw Utils.makeError(cx, this, "Error initializing cipher: " + gse);
            }

            initialized = true;
        }

        protected static Object updateInternal(Context cx, Scriptable thisObj, Object[] args)
        {
            ensureArg(args, 0);
            String encoding = stringArg(args, 1, null);
            AbstractCipherImpl self = (AbstractCipherImpl)thisObj;

            if (!self.initialized) {
                self.initialize(cx);
            }

            byte[] result;
            if (args[0] instanceof String) {
                ByteBuffer bb = Utils.stringToBuffer(stringArg(args, 0),
                                                     Charsets.get().resolveCharset(encoding));
                result = self.cipher.update(bb.array(), bb.arrayOffset(), bb.limit());
            } else {
                Buffer.BufferImpl buf = objArg(args, 0, Buffer.BufferImpl.class, true);
                result = self.cipher.update(buf.getArray(), buf.getArrayOffset(), buf.getLength());
            }

            if (result == null) {
                result = EMPTY_BUF;
            }
            return Buffer.BufferImpl.newBuffer(cx, thisObj, result);
        }

        protected static Object finalInternal(Context cx, Scriptable thisObj, Object[] args)
        {
            AbstractCipherImpl self = (AbstractCipherImpl)thisObj;

            if (!self.initialized) {
                self.initialize(cx);
            }

            byte[] result;
            try {
                result = self.cipher.doFinal();
            } catch (GeneralSecurityException gse) {
                throw Utils.makeError(cx, thisObj, "Cryptography error: " + gse);
            }

            if (result == null) {
                result = EMPTY_BUF;
            }
            return Buffer.BufferImpl.newBuffer(cx, thisObj, result);
        }
    }

    public static class CipherImpl
        extends AbstractCipherImpl
    {
        public static final String CLASS_NAME = "Cipher";

        @Override
        public String getClassName()
        {
            return CLASS_NAME;
        }

        @Override
        protected int getMode()
        {
            return Cipher.ENCRYPT_MODE;
        }

        @JSFunction
        public static void init(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            initInternal(cx, thisObj, args);
        }

        @JSFunction
        public static void setAutoPadding(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            setAutoPaddingInternal(cx, thisObj, args);
        }

        @JSFunction("final")
        public static Object doFinal(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            return finalInternal(cx, thisObj, args);
        }

        @JSFunction
        public static Object update(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            return updateInternal(cx, thisObj, args);
        }
    }

    public static class DecipherImpl
        extends AbstractCipherImpl
    {
        public static final String CLASS_NAME = "Decipher";

        @Override
        public String getClassName()
        {
            return CLASS_NAME;
        }

        @Override
        protected int getMode()
        {
            return Cipher.DECRYPT_MODE;
        }

        @JSFunction
        public static void init(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            initInternal(cx, thisObj, args);
        }

        @JSFunction
        public static void setAutoPadding(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            setAutoPaddingInternal(cx, thisObj, args);
        }

        @JSFunction("final")
        public static Object doFinal(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            return finalInternal(cx, thisObj, args);
        }

        @JSFunction
        public static Object update(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            return updateInternal(cx, thisObj, args);
        }
    }

    public static class SignImpl
        extends ScriptableObject
    {
        public static final String CLASS_NAME = "Sign";

        /*
         * Aargh. To make this work, we will need to:
         *
         * . Convert PEM-encoded keys to DER (code already in Utils)
         * . Extract RSA private key info from the DER, by parsing the ASN.1
         * . Generate the RSA private key
         * . We may be better off plugging in Bouncy Castle as an optional dependency
         */

        @Override
        public String getClassName()
        {
            return CLASS_NAME;
        }

        @JSConstructor
        public static void init(Context cx, Object[] args, Function ctorObj, boolean inNewExpr)
        {
            throw Utils.makeError(cx, ctorObj, "crypto signatures are not supported in Noderunner");
        }
    }

    public static class SecureContextImpl
        extends ScriptableObject
    {
        public static final String CLASS_NAME = "SecureContext";

        /*
         * This appears to be used solely by TLS, and we do that differently in our implementation,
         * so leave it out.
         */

        @Override
        public String getClassName()
        {
            return CLASS_NAME;
        }

        @JSConstructor
        public static void init(Context cx, Object[] args, Function ctorObj, boolean inNewExpr)
        {
            throw Utils.makeError(cx, ctorObj, "crypto credentials not supported in Noderunner");
        }
    }
}
