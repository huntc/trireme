/**
 * Copyright 2013 Apigee Corporation.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package io.apigee.trireme.core.modules;

import io.apigee.trireme.core.NodeModule;
import io.apigee.trireme.core.NodeRuntime;
import io.apigee.trireme.core.internal.NodeExitException;
import io.apigee.trireme.core.internal.ScriptRunner;
import io.apigee.trireme.core.Utils;
import io.apigee.trireme.core.internal.Version;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.EvaluatorException;
import org.mozilla.javascript.Function;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.ScriptableObject;
import org.mozilla.javascript.annotations.JSConstructor;
import org.mozilla.javascript.annotations.JSFunction;
import org.mozilla.javascript.annotations.JSGetter;
import org.mozilla.javascript.annotations.JSSetter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static io.apigee.trireme.core.ArgUtils.*;

import java.lang.reflect.InvocationTargetException;
import java.util.Map;

/**
 * The Node process module done on top of the VM.
 */
public class Process
    implements NodeModule
{
    protected static final String OBJECT_NAME = "process";
    public static final String MODULE_NAME = "process";
    public static final String EXECUTABLE_NAME = "./node";
    /** We don't really know what the umask is in Java, so we set a reasonable default that the tests expected. */
    public static final int DEFAULT_UMASK = 022;

    private static final   long NANO = 1000000000L;
    protected static final Logger log  = LoggerFactory.getLogger(Process.class);

    @Override
    public String getModuleName()
    {
        return MODULE_NAME;
    }

    @Override
    public Scriptable registerExports(Context cx, Scriptable scope, NodeRuntime runner)
        throws InvocationTargetException, IllegalAccessException, InstantiationException
    {
        ScriptableObject.defineClass(scope, EventEmitter.EventEmitterImpl.class, false, true);


        ScriptableObject.defineClass(scope, ProcessImpl.class, false, true);
        ScriptableObject.defineClass(scope, EnvImpl.class, false, true);

        ProcessImpl exports = (ProcessImpl) cx.newObject(scope, ProcessImpl.CLASS_NAME);
        exports.setRunner(cx, runner);

        EnvImpl env = (EnvImpl) cx.newObject(scope, EnvImpl.CLASS_NAME);
        env.initialize(runner.getScriptObject().getEnvironment());
        exports.setEnv(env);

        // Put the object directly in the scope -- we only do this for modules that are always deployed
        // as global variables in the script.
        scope.put(OBJECT_NAME, scope, exports);
        return exports;
    }

    public static class ProcessImpl
        extends EventEmitter.EventEmitterImpl
    {
        protected static final String CLASS_NAME = "_processClass";

        private Scriptable stdout;
        private Scriptable stderr;
        private Scriptable stdin;
        private Scriptable argv;
        private Scriptable env;
        private Object eventEmitter;
        private long startTime;
        private ScriptRunner runner;
        private Object mainModule;
        private boolean needImmediateCallback;
        private Function immediateCallback;
        private Object domain;
        private boolean usingDomains;
        private boolean exiting;
        private NodeExitException exitStatus;
        private int umask = DEFAULT_UMASK;

        @JSConstructor
        public static Object ProcessImpl(Context cx, Object[] args, Function ctorObj, boolean inNewExpr)
        {
            ProcessImpl ret = new ProcessImpl();
            ret.startTime = System.currentTimeMillis();
            return ret;
        }

        @Override
        public String getClassName() {
            return CLASS_NAME;
        }

        public void setRunner(Context cx, NodeRuntime runner)
        {
            // This is a low-level module and it's OK to access low-level stuff
            this.runner = (ScriptRunner)runner;

            Scriptable eventModule = (Scriptable)runner.require("events", cx);
            this.eventEmitter = ScriptableObject.getProperty(eventModule, "EventEmitter");
        }

        @JSGetter("mainModule")
        public Object getMainModule() {
            return mainModule;
        }

        @JSSetter("mainModule")
        public void setMainModule(Object m) {
            this.mainModule = m;
        }

        /**
         * Implement process.binding. This works like the rest of the module loading but uses a different
         * namespace and a different cache. These types of modules must be implemented in Java.
         */
        @JSFunction
        public static Object binding(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            String name = stringArg(args, 0);
            ProcessImpl proc = (ProcessImpl)thisObj;

            return proc.getInternalModule(name, cx);
        }

        public Object getInternalModule(String name, Context cx)
        {
            Object mod = runner.getCachedInternalModule(name);
            if (mod == null) {
                try {
                    mod = runner.initializeModule(name, true, cx, runner.getScriptScope());
                    if (log.isTraceEnabled()) {
                        log.trace("Creating new instance {} of internal module {}",
                                  System.identityHashCode(mod), name);
                    }
                    // Special handling of "buffer" which is available in more than one context
                    if ((mod == null) && Buffer.MODULE_NAME.equals(name)) {
                        return runner.require(name, cx);
                    }

                } catch (InvocationTargetException e) {
                    Throwable targetException = e.getTargetException();
                    throw new EvaluatorException("Error initializing module: " +
                            ((targetException != null) ?
                                    e.toString() + ": " + targetException.toString() :
                                    e.toString()));
                } catch (InstantiationException e) {
                    throw new EvaluatorException("Error initializing module: " + e.toString());
                 } catch (IllegalAccessException e) {
                    throw new EvaluatorException("Error initializing module: " + e.toString());
                }
                runner.cacheInternalModule(name, mod);
            } else if (log.isTraceEnabled()) {
                log.trace("Returning cached copy {} of internal module {}",
                          System.identityHashCode(mod), name);
            }
            return mod;
        }

        @JSGetter("stdout")
        public Object getStdout()
        {
            if (stdout == null) {
                Context cx = Context.getCurrentContext();
                runner.requireInternal(NativeOutputStreamAdapter.MODULE_NAME, cx);
                stdout =
                    NativeOutputStreamAdapter.createNativeStream(cx,
                                                                 runner.getScriptScope(), runner,
                                                                 runner.getStdout(), true);

                // node "legacy API" -- use POSIX file descriptor number
                stdout.put("fd", stdout, 1);
            }
            return stdout;
        }

        public void setStdout(Scriptable s)
        {
            this.stdout = s;
        }

        @JSGetter("stderr")
        public Object getStderr()
        {
            if (stderr == null) {
                Context cx = Context.getCurrentContext();
                runner.requireInternal(NativeOutputStreamAdapter.MODULE_NAME, cx);
                stderr =
                    NativeOutputStreamAdapter.createNativeStream(cx,
                                                                 runner.getScriptScope(), runner,
                                                                 runner.getStderr(), true);

                // node "legacy API" -- use POSIX file descriptor number
                stderr.put("fd", stderr, 2);
            }
            return stderr;
        }

        public void setStderr(Scriptable s)
        {
            this.stderr = s;
        }

        @JSGetter("stdin")
        public Object getStdin()
        {
            if (stdin == null) {
                Context cx = Context.getCurrentContext();
                runner.requireInternal(NativeInputStreamAdapter.MODULE_NAME, cx);
                stdin =
                    NativeInputStreamAdapter.createNativeStream(cx,
                                                                runner.getScriptScope(), runner,
                                                                runner.getStdin(), true);

                // node "legacy API" -- use POSIX file descriptor number
                stdin.put("fd", stdin, 0);
            }
            return stdin;
        }

        public void setStdin(Scriptable s)
        {
            this.stdin = s;
        }

        @JSGetter("argv")
        public Object getArgv()
        {
            return argv;
        }

        public void setArgv(String[] args)
        {
            Object[] argvArgs = new Object[args.length];
            for (int i = 0; i < args.length; i++) {
                argvArgs[i] = args[i];
            }
            argv = Context.getCurrentContext().newArray(this, argvArgs);
        }

        @JSGetter("execArgv")
        public Object getExecArgv()
        {
            return Context.getCurrentContext().newArray(this, 0);
        }

        public void setEnv(EnvImpl env) {
            this.env = env;
        }

        @JSGetter("execPath")
        public String getExecPath()
        {
            return EXECUTABLE_NAME;
        }

        @JSFunction
        public void abort()
            throws NodeExitException
        {
            exitStatus = new NodeExitException(NodeExitException.Reason.FATAL);
            throw exitStatus;
        }

        @JSFunction
        public void chdir(String cd)
        {
            runner.setWorkingDirectory(cd);
        }

        @JSFunction
        public String cwd()
        {
            return runner.getWorkingDirectory();
        }

        @JSGetter("env")
        public Scriptable getEnv()
        {
            return env;
        }

        @JSFunction
        public static void exit(Context cx, Scriptable thisObj, Object[] args, Function func)
            throws NodeExitException
        {
            ProcessImpl self = (ProcessImpl)thisObj;
            if (args.length >= 1) {
                int code = (Integer)Context.jsToJava(args[0], Integer.class);
                self.exitStatus = new NodeExitException(NodeExitException.Reason.NORMAL, code);
            } else {
                self.exitStatus = new NodeExitException(NodeExitException.Reason.NORMAL, 0);
            }
            throw self.exitStatus;
        }

        @JSFunction
        public static void reallyExit(Context cx, Scriptable thisObj, Object[] args, Function func)
            throws NodeExitException
        {
            // In regular node this calls the "exit" system call but we are run inside a bigger context so no.
            exit(cx, thisObj, args, func);
        }

        // TODO getgid
        // TODO setgid
        // TODO getuid
        // TODO setuid

        @JSGetter("version")
        public String getVersion()
        {
            return "v" + Version.NODE_VERSION;
        }

        @JSGetter("versions")
        public Object getVersions()
        {
            Scriptable env = Context.getCurrentContext().newObject(this);
            env.put("trireme", env, Version.TRIREME_VERSION);
            env.put("node", env, Version.NODE_VERSION);
            env.put("openssl", env, Version.SSL_VERSION);
            return env;
        }

        @JSGetter("config")
        public Scriptable getConfig()
        {
            Scriptable c = Context.getCurrentContext().newObject(this);
            Scriptable vars = Context.getCurrentContext().newObject(this);
            // TODO fill it in
            c.put("variables", c, vars);
            return c;
        }

        @JSGetter("title")
        public String getTitle()
        {
            return "trireme";
        }

        @JSSetter("title")
        public void setTitle(String title)
        {
            // You can't set it
        }

        @JSGetter("arch")
        public String getArch()
        {
            // This is actually the bitness of the JRE, not necessarily the system
            String arch = System.getProperty("os.arch");

            if (arch.equals("x86")) {
                return "ia32";
            } else if (arch.equals("x86_64")) {
                return "x64";
            }

            return arch;
        }

        @JSFunction
        public static void kill(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            int pid = intArg(args, 0);
            String signal = stringArg(args, 1, "TERM");
            if ("0".equals(signal)) {
                signal = null;
            }

            ProcessWrap.kill(cx, thisObj, pid, signal);
        }

        @JSGetter("pid")
        public int getPid()
        {
            // Java doesn't give us the OS pid. However this is used for debug to show different Node scripts
            // on the same machine, so return a value that uniquely identifies this ScriptRunner.
            return System.identityHashCode(runner) % 65536;
        }

        @JSFunction
        public static void send(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            Object message = objArg(args, 0, Object.class, true);
            ProcessImpl self = (ProcessImpl)thisObj;

            if (self.runner.getParentProcess() == null) {
                throw Utils.makeError(cx, thisObj, "IPC is not enabled back to the parent");
            }

            ProcessWrap.ProcessImpl pw = (ProcessWrap.ProcessImpl)self.runner.getParentProcess();
            pw.getOnMessage().call(cx, pw, pw, new Object[] { message });
        }

        @JSGetter("_errno")
        public Object getErrno()
        {
            return runner.getErrno();
        }

        @JSGetter("platform")
        public String getPlatform()
        {
            return "java";
        }

        @JSFunction
        public static Object memoryUsage(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            Runtime r = Runtime.getRuntime();
            Scriptable mem = cx.newObject(thisObj);
            mem.put("rss", mem, r.totalMemory());
            mem.put("heapTotal", mem, r.maxMemory());
            mem.put("heapUsed", mem,  r.totalMemory());
            return mem;
        }

        @JSFunction
        public static void _usingDomains(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            ((ProcessImpl)thisObj).usingDomains = true;
        }

        @JSFunction
        public static void nextTick(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            Function f = functionArg(args, 0, true);
            ProcessImpl proc = (ProcessImpl)thisObj;
            Scriptable domain = null;
            if (proc.usingDomains) {
                domain = ensureValid(proc.domain);
            }
            proc.runner.enqueueCallbackWithLimit(f, f, thisObj, domain, new Object[0]);
        }

        @JSFunction
        public static void _tickCallback(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            ProcessImpl proc = (ProcessImpl)thisObj;
            proc.runner.executeTicks(cx);
        }

        @JSGetter("maxTickDepth")
        public int getMaxTickDepth()
        {
            return runner.getMaxTickDepth();
        }

        @JSSetter("maxTickDepth")
        public void setMaxTickDepth(double depth)
        {
            if (Double.isInfinite(depth)) {
                runner.setMaxTickDepth(Integer.MAX_VALUE);
            } else {
                runner.setMaxTickDepth((int)depth);
            }
        }

        @JSSetter("_needImmediateCallback")
        public void setNeedImmediateCallback(boolean n)
        {
            this.needImmediateCallback = n;
        }

        @JSGetter("_needImmediateCallback")
        public boolean isNeedImmediateCallback()
        {
            return needImmediateCallback;
        }

        @JSSetter("_immediateCallback")
        public void setImmediateCallback(Function f)
        {
            this.immediateCallback = f;
        }

        @JSGetter("_immediateCallback")
        public Function getImmediateCallback()
        {
            return immediateCallback;
        }

        public void checkImmediateTasks(Context cx)
        {
            while (needImmediateCallback) {
                immediateCallback.call(cx, immediateCallback, null, null);
            }
        }

        @JSFunction
        public static Object umask(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            ProcessImpl self = (ProcessImpl)thisObj;
            if (args.length > 0) {
                int oldMask = self.umask;
                int newMask = octalOrHexIntArg(args, 0);
                self.umask = newMask;
                return Context.toNumber(oldMask);
            } else {
                return Context.toNumber(self.umask);
            }
        }

        public int getUmask()
        {
            return umask;
        }

        @JSFunction
        public static Object uptime(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            ProcessImpl self = (ProcessImpl)thisObj;
            long up = (System.currentTimeMillis() - self.startTime) / 1000L;
            return Context.javaToJS(up, thisObj);
        }

        @JSFunction
        public static Object hrtime(Context cx, Scriptable thisObj, Object[] args, Function func)
        {
            long nanos = System.nanoTime();
            if (args.length == 1) {
                Scriptable arg = ensureScriptable(args[0]);
                if (!arg.has(0, arg) || !arg.has(1, arg)) {
                    throw new EvaluatorException("Argument must be an array");
                }
                long startSecs = (long)Context.toNumber(arg.get(0, arg));
                long startNs = (long)Context.toNumber(arg.get(1, arg));
                long startNanos = ((startSecs * NANO) + startNs);
                nanos -= startNanos;
            } else if (args.length > 1) {
                throw new EvaluatorException("Invalid arguments");
            }

            Object[] ret = new Object[2];
            ret[0] = (int)(nanos / NANO);
            ret[1] = (int)(nanos % NANO);
            return cx.newArray(thisObj, ret);
        }

        @JSGetter("features")
        public Object getFeatures()
        {
            Scriptable features = Context.getCurrentContext().newObject(this);
            return features;
        }

        @JSGetter("domain")
        public Object getDomain()
        {
            return domain;
        }

        @JSSetter("domain")
        public void setDomain(Object d)
        {
            this.domain = d;
        }

        @JSGetter("_exiting")
        public boolean isExiting()
        {
            return exiting;
        }

        @JSSetter("_exiting")
        public void setExiting(boolean e)
        {
            this.exiting = e;
        }

        public NodeExitException getExitStatus()
        {
            return exitStatus;
        }

        public void setExitStatus(NodeExitException ne)
        {
            this.exitStatus = ne;
        }

        @JSGetter("EventEmitter")
        public Object getEventEmitter()
        {
            return this.eventEmitter;
        }
    }

    public static class EnvImpl
            extends ScriptableObject
    {
        public static final String CLASS_NAME = "_Environment";

        @Override
        public String getClassName() {
            return CLASS_NAME;
        }

        void initialize(Map<String, String> env)
        {
            for (Map.Entry<String, String> ee : env.entrySet()) {
                this.put(ee.getKey(), this, ee.getValue());
            }
        }
    }

}
