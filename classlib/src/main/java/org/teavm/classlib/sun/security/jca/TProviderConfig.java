/*
 *  Copyright 2021 Alexander.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.teavm.classlib.sun.security.jca;

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.security.ProviderException;
import org.teavm.classlib.java.security.TProvider;
import sun.security.util.PropertyExpander;

public class TProviderConfig {

    private final static sun.security.util.Debug debug =
            sun.security.util.Debug.getInstance("jca", "ProviderConfig");

    // classname of the SunPKCS11-Solaris provider
    private static final String P11_SOL_NAME =
            "sun.security.pkcs11.SunPKCS11";

    // config file argument of the SunPKCS11-Solaris provider
    private static final String P11_SOL_ARG  =
            "${java.home}/lib/security/sunpkcs11-solaris.cfg";

    // maximum number of times to try loading a provider before giving up
    private final static int MAX_LOAD_TRIES = 30;

    // parameters for the Provider(String) constructor,
    // use by doLoadProvider()
    private final static Class[] CL_STRING = { String.class };

    // name of the provider class
    private final String className;

    // argument to the provider constructor,
    // empty string indicates no-arg constructor
    private final String argument;

    // number of times we have already tried to load this provider
    private int tries;

    // Provider object, if loaded
    private volatile TProvider provider;

    // flag indicating if we are currently trying to load the provider
    // used to detect recursion
    private boolean isLoading;

    TProviderConfig(String className, String argument) {
        if (className.equals(P11_SOL_NAME) && argument.equals(P11_SOL_ARG)) {
            checkSunPKCS11Solaris();
        }
        this.className = className;
        this.argument = expand(argument);
    }

    TProviderConfig(String className) {
        this(className, "");
    }

    TProviderConfig(TProvider provider) {
        this.className = provider.getClass().getName();
        this.argument = "";
        this.provider = provider;
    }

    // check if we should try to load the SunPKCS11-Solaris provider
    // avoid if not available (pre Solaris 10) to reduce startup time
    // or if disabled via system property
    private void checkSunPKCS11Solaris() {
        Boolean o = AccessController.doPrivileged(
                new PrivilegedAction<Boolean>() {
                    public Boolean run() {
                        File file = new File("/usr/lib/libpkcs11.so");
                        if (file.exists() == false) {
                            return Boolean.FALSE;
                        }
                        if ("false".equalsIgnoreCase(System.getProperty
                                ("sun.security.pkcs11.enable-solaris"))) {
                            return Boolean.FALSE;
                        }
                        return Boolean.TRUE;
                    }
                });
        if (o == Boolean.FALSE) {
            tries = MAX_LOAD_TRIES;
        }
    }

    private boolean hasArgument() {
        return argument.length() != 0;
    }

    // should we try to load this provider?
    private boolean shouldLoad() {
        return (tries < MAX_LOAD_TRIES);
    }

    // do not try to load this provider again
    private void disableLoad() {
        tries = MAX_LOAD_TRIES;
    }

    boolean isLoaded() {
        return (provider != null);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof TProviderConfig == false) {
            return false;
        }
        TProviderConfig other = (TProviderConfig)obj;
        return this.className.equals(other.className)
                && this.argument.equals(other.argument);
    }

    public int hashCode() {
        return className.hashCode() + argument.hashCode();
    }

    public String toString() {
        if (hasArgument()) {
            return className + "('" + argument + "')";
        } else {
            return className;
        }
    }

    /**
     * Get the provider object. Loads the provider if it is not already loaded.
     */
    synchronized TProvider getProvider() {
        // volatile variable load
        TProvider p = provider;
        if (p != null) {
            return p;
        }
        if (shouldLoad() == false) {
            return null;
        }
        if (isLoading) {
            // because this method is synchronized, this can only
            // happen if there is recursion.
            if (debug != null) {
                debug.println("Recursion loading provider: " + this);
                new Exception("Call trace").printStackTrace();
            }
            return null;
        }
        try {
            isLoading = true;
            tries++;
            p = doLoadProvider();
        } finally {
            isLoading = false;
        }
        provider = p;
        return p;
    }

    private TProvider doLoadProvider() {
        return AccessController.doPrivileged(new PrivilegedAction<TProvider>() {
            public TProvider run() {
                if (debug != null) {
                    debug.println("Loading provider: " + TProviderConfig.this);
                }
                try {
                    ClassLoader cl = ClassLoader.getSystemClassLoader();
                    Class<?> provClass;
                    if (cl != null) {
                        provClass = cl.loadClass(className);
                    } else {
                        provClass = Class.forName(className);
                    }
                    Object obj;
                    if (hasArgument() == false) {
                        obj = provClass.newInstance();
                    } else {
                        Constructor<?> cons = provClass.getConstructor(CL_STRING);
                        obj = cons.newInstance(argument);
                    }
                    if (obj instanceof TProvider) {
                        if (debug != null) {
                            debug.println("Loaded provider " + obj);
                        }
                        return (TProvider)obj;
                    } else {
                        if (debug != null) {
                            debug.println(className + " is not a provider");
                        }
                        disableLoad();
                        return null;
                    }
                } catch (Exception e) {
                    Throwable t;
                    if (e instanceof InvocationTargetException) {
                        t = ((InvocationTargetException)e).getCause();
                    } else {
                        t = e;
                    }
                    if (debug != null) {
                        debug.println("Error loading provider " + TProviderConfig.this);
                        t.printStackTrace();
                    }
                    // provider indicates fatal error, pass through exception
                    if (t instanceof ProviderException) {
                        throw (ProviderException)t;
                    }
                    // provider indicates that loading should not be retried
                    if (t instanceof UnsupportedOperationException) {
                        disableLoad();
                    }
                    return null;
                } catch (ExceptionInInitializerError err) {
                    // unexpected exception thrown from static initialization block in provider
                    // (ex: insufficient permission to initialize provider class)
                    if (debug != null) {
                        debug.println("Error loading provider " + TProviderConfig.this);
                        err.printStackTrace();
                    }
                    disableLoad();
                    return null;
                }
            }
        });
    }

    /**
     * Perform property expansion of the provider value.
     *
     * NOTE use of doPrivileged().
     */
    private static String expand(final String value) {
        // shortcut if value does not contain any properties
        if (value.contains("${") == false) {
            return value;
        }
        return AccessController.doPrivileged(new PrivilegedAction<String>() {
            public String run() {
                try {
                    return PropertyExpander.expand(value);
                } catch (GeneralSecurityException e) {
                    throw new ProviderException(e);
                }
            }
        });
    }

}

