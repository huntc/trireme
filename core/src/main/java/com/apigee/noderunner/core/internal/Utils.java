package com.apigee.noderunner.core.internal;

import com.apigee.noderunner.core.modules.Constants;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.JavaScriptException;
import org.mozilla.javascript.RhinoException;
import org.mozilla.javascript.Scriptable;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.util.ArrayList;
import java.util.List;

/**
 * A few utility functions.
 */
public class Utils
{
    public static final Charset UTF8 = Charset.forName("UTF-8");

    public static String readStream(InputStream in)
        throws IOException
    {
        InputStreamReader rdr = new InputStreamReader(in, UTF8);
        StringBuilder str = new StringBuilder();
        char[] buf = new char[4096];
        int r;
        do {
            r = rdr.read(buf);
            if (r > 0) {
                str.append(buf, 0, r);
            }
        } while (r > 0);
        return str.toString();
    }

    public static byte[] readBinaryStream(InputStream in)
        throws IOException
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int r;
        do {
            r = in.read(buf);
            if (r > 0) {
                bos.write(buf, 0, r);
            }
        } while (r > 0);
        return bos.toByteArray();
    }

    public static String readFile(File f)
        throws IOException
    {
        FileInputStream in = new FileInputStream(f);
        try {
            return readStream(in);
        } finally {
            in.close();
        }
    }

    public static Reader getResource(String name)
    {
        InputStream is = ScriptRunner.class.getResourceAsStream(name);
        if (is == null) {
            return null;
        }
        return new InputStreamReader(is);
    }

    public static Method findMethod(Class<?> klass, String name)
    {
        for (Method m : klass.getMethods()) {
            if (name.equals(m.getName())) {
                return m;
            }
        }
        return null;
    }

    public static String bufferToString(ByteBuffer buf, Charset cs)
    {
        CharsetDecoder decoder = cs.newDecoder();
        int bufLen = (int)(buf.limit() * decoder.averageCharsPerByte());
        CharBuffer cBuf = CharBuffer.allocate(bufLen);
        CoderResult result;
        do {
            result = decoder.decode(buf, cBuf, true);
            if (result.isOverflow()) {
                bufLen *= 2;
                CharBuffer newBuf = CharBuffer.allocate(bufLen);
                cBuf.flip();
                newBuf.put(cBuf);
                cBuf = newBuf;
            }
        } while (result.isOverflow());

        cBuf.flip();
        return cBuf.toString();
    }

    public static String bufferToString(ByteBuffer[] bufs, Charset cs)
    {
        CharsetDecoder decoder = cs.newDecoder();
        int totalBytes = 0;
        for (int i = 0; i < bufs.length; i++) {
            totalBytes += (bufs[i] == null ? 0 : bufs[i].remaining());
        }
        int bufLen = (int)(totalBytes * decoder.averageCharsPerByte());
        CharBuffer cBuf = CharBuffer.allocate(bufLen);
        CoderResult result;
        for (int i = 0; i < bufs.length; i++) {
            do {
                result = decoder.decode(bufs[i], cBuf, true);
                if (result.isOverflow()) {
                    bufLen *= 2;
                    CharBuffer newBuf = CharBuffer.allocate(bufLen);
                    cBuf.flip();
                    newBuf.put(cBuf);
                    cBuf = newBuf;
                }
            } while (result.isOverflow());
        }

        cBuf.flip();
        return cBuf.toString();
    }

    public static ByteBuffer stringToBuffer(CharSequence str, Charset cs)
    {
        CharsetEncoder enc = cs.newEncoder();
        CharBuffer chars = CharBuffer.wrap(str);
        int bufLen = (int)(chars.remaining() * enc.averageBytesPerChar());
        ByteBuffer writeBuf =  ByteBuffer.allocate(bufLen);
        enc.onUnmappableCharacter(CodingErrorAction.REPLACE);

        CoderResult result;
        do {
            result = enc.encode(chars, writeBuf, true);
            if (result == CoderResult.OVERFLOW) {
                bufLen *= 2;
                ByteBuffer newBuf = ByteBuffer.allocate(bufLen);
                writeBuf.flip();
                newBuf.put(writeBuf);
                writeBuf = newBuf;
            }
        } while (result == CoderResult.OVERFLOW);

        writeBuf.flip();
        return writeBuf;
    }

    public static Scriptable makeErrorObject(Context cx, Scriptable scope, String message)
    {
        return cx.newObject(scope, "Error", new Object[] { message });
    }

    public static Scriptable makeErrorObject(Context cx, Scriptable scope, String message, RhinoException re)
    {
        Scriptable e = cx.newObject(scope, "Error", new Object[] { message });
        e.put("stack", e, re.getScriptStackTrace());
        return e;
    }

    public static RhinoException makeError(Context cx, Scriptable scope, String message)
    {
        return new JavaScriptException(makeErrorObject(cx, scope, message));
    }

    public static RhinoException makeError(Context cx, Scriptable scope, String message, RhinoException re)
    {
        return new JavaScriptException(makeErrorObject(cx, scope, message, re));
    }

    public static Scriptable makeErrorObject(Context cx, Scriptable scope, String message, String code)
    {
        return makeErrorObject(cx, scope, message, code, null);
    }

    public static Scriptable makeErrorObject(Context cx, Scriptable scope, String message, String code, String path)
    {
        Scriptable err = cx.newObject(scope, "Error", new Object[] { message });
        err.put("code", err, code);
        int errno = Constants.getErrno(code);
        if (errno >= 0) {
            err.put("errno", err, errno);
        }
        if (path != null) {
            err.put("path", err, path);
        }
        return err;
    }

    public static RhinoException makeError(Context cx, Scriptable scope, String message, String code)
    {
        return new JavaScriptException(makeErrorObject(cx, scope, message, code));
    }

    public static RhinoException makeError(Context cx, Scriptable scope, NodeOSException e)
    {
        return new JavaScriptException(makeErrorObject(cx, scope, e));
    }

    public static Scriptable makeErrorObject(Context cx, Scriptable scope, NodeOSException e)
    {
        return makeErrorObject(cx, scope, e.getMessage(), e.getCode(), e.getPath());
    }

    public static RhinoException makeRangeError(Context cx, Scriptable scope, String message)
    {
        Scriptable err = cx.newObject(scope, "RangeError", new Object[] { message });
        return new JavaScriptException(err);
    }

    public static RhinoException makeTypeError(Context cx, Scriptable scope, String message)
    {
        Scriptable err = cx.newObject(scope, "TypeError", new Object[] { message });
        return new JavaScriptException(err);
    }


    public static List<String> toStringList(Scriptable o)
    {
        ArrayList<String> ret = new ArrayList<String>();
        for (Object id : o.getIds()) {
            Object val;
            if (id instanceof Integer) {
                val = o.get((Integer)id, o);
            } else {
                val = o.get((String)id, o);
            }
            ret.add(Context.toString(val));
        }
        return ret;
    }

    private static final int BASE64_LINELEN = 64;

    /**
     * Convert binary data to "PEM" by adding BEGIN WHATEVER and END WHATEVER wrappers and then
     * base64-encoding the rest.
     *
     * @param typeMarker what to put after BEGIN and END like "CERTIFICATE" or whatever
     */
    public static String derToPem(ByteBuffer der, String typeMarker)
    {
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN " + typeMarker + "-----\n");
        String base64 = bufferToString(der, Charsets.BASE64);

        int pos = 0;
        do {
            int len = Math.min((base64.length() - pos), BASE64_LINELEN);
            pem.append(base64.substring(pos, pos + len));
            pem.append('\n');
            pos += len;
        } while (pos < base64.length());

        pem.append("-----END " + typeMarker + "-----\n");
        return pem.toString();
    }

    /**
     * Convert "PEM" data to binary by stripping off the BEGIN and END lines and
     * then base64-decoding the rest.
     */
    public static ByteBuffer pemToDer(String pem)
    {
        BufferedReader rdr = new BufferedReader(new StringReader(pem));
        StringBuilder base64 = new StringBuilder();

        try {
            String line = rdr.readLine();
            while ((line != null) && !line.startsWith("-----BEGIN")) {
                line = rdr.readLine();
            }
            // We read BEGIN -- now read on
            if (line != null) {
                line = rdr.readLine();
            }

            while ((line != null) && !line.startsWith("-----END")) {
                base64.append(line);
                line = rdr.readLine();
            }
        } catch (IOException ioe) {
            throw new AssertionError(ioe);
        }

        return stringToBuffer(base64, Charsets.BASE64);
    }
}
