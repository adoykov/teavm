/*
 *  Copyright 2021 R3 Ltd.
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
package org.teavm.classlib.java.security;

import static java.util.Locale.ENGLISH;
import java.lang.ref.Reference;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.teavm.classlib.java.lang.TNumberFormatException;
import org.teavm.classlib.java.util.TCollection;
import org.teavm.classlib.java.util.TCollections;
import org.teavm.classlib.java.util.TProperties;
import org.teavm.classlib.java.util.TSet;

public abstract class TProvider extends TProperties {
    private String name;
    private String info;
    private double version;
    private String versionStr;
    private transient boolean initialized;

    @Deprecated
    protected TProvider(String name, double version, String info) {
        this.name = name;
        this.version = version;
        this.versionStr = Double.toString(version);
        this.info = info;
    }

    protected TProvider(String name, String versionStr, String info) {
        this.name = name;
        this.versionStr = versionStr;
        try {
            this.version = Double.parseDouble(versionStr);
        } catch (TNumberFormatException e) {
            this.version = 0.0;
        }
        this.info = info;
    }

    public TProvider configure(String configArg) {
        throw new UnsupportedOperationException("configure is not supported");
    }

    public boolean isConfigured() {
        return true;
    }


    public String getName() {
        return name;
    }

    @Deprecated
    public double getVersion() {
        return version;
    }

    public String getInfo() {
        return info;
    }

    public String toString() {
        return name + " version " + versionStr;
    }

    @Override
    public synchronized void clear() {
    }

    /**
     * Returns an unmodifiable Set view of the property keys contained in
     * this provider.
     *
     * @since 1.2
     */
    @Override
    public TSet<Object> keySet() {
        return TCollections.unmodifiableSet(super.keySet());
    }

    /**
     * Returns an unmodifiable Collection view of the property values
     * contained in this provider.
     *
     * @since 1.2
     */
    @Override
    public TCollection<Object> values() {
        return TCollections.unmodifiableCollection(super.values());
    }

    private void checkInitialized() {
        if (!initialized) {
            throw new IllegalStateException();
        }
    }

    private static class ServiceKey {
        private final String type;
        private final String algorithm;
        private final String originalAlgorithm;
        private ServiceKey(String type, String algorithm, boolean intern) {
            this.type = type;
            this.originalAlgorithm = algorithm;
            algorithm = algorithm.toUpperCase(ENGLISH);
            this.algorithm = intern ? algorithm.intern() : algorithm;
        }
        public int hashCode() {
            return type.hashCode() + algorithm.hashCode();
        }
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof ServiceKey)) {
                return false;
            }
            TProvider.ServiceKey other = (TProvider.ServiceKey)obj;
            return this.type.equals(other.type)
                    && this.algorithm.equals(other.algorithm);
        }
        boolean matches(String type, String algorithm) {
            return (this.type == type) && (this.originalAlgorithm == algorithm);
        }
    }

    private transient Map<TProvider.ServiceKey, TProvider.Service> serviceMap;

    private static volatile TProvider.ServiceKey previousKey =
            new TProvider.ServiceKey("", "", false);

    private transient boolean legacyChanged;
    private transient Map<String,String> legacyStrings;
    private transient Map<TProvider.ServiceKey, TProvider.Service> legacyMap;
    private transient Set<Provider.Service> serviceSet;

    private static final sun.security.util.Debug debug =
            sun.security.util.Debug.getInstance
                    ("provider", "Provider");

    private String[] getTypeAndAlgorithm(String key) {
        int i = key.indexOf(".");
        if (i < 1) {
            if (debug != null) {
                debug.println("Ignoring invalid entry in provider "
                        + name + ":" + key);
            }
            return null;
        }
        String type = key.substring(0, i);
        String alg = key.substring(i + 1);
        return new String[] {type, alg};
    }

    private final static String ALIAS_PREFIX = "Alg.Alias.";
    private final static String ALIAS_PREFIX_LOWER = "alg.alias.";
    private final static int ALIAS_LENGTH = ALIAS_PREFIX.length();

    private void parseLegacyPut(String name, String value) {
        if (name.toLowerCase(ENGLISH).startsWith(ALIAS_PREFIX_LOWER)) {
            // e.g. put("Alg.Alias.MessageDigest.SHA", "SHA-1");
            // aliasKey ~ MessageDigest.SHA
            String stdAlg = value;
            String aliasKey = name.substring(ALIAS_LENGTH);
            String[] typeAndAlg = getTypeAndAlgorithm(aliasKey);
            if (typeAndAlg == null) {
                return;
            }
            String type = getEngineName(typeAndAlg[0]);
            String aliasAlg = typeAndAlg[1].intern();
            TProvider.ServiceKey key = new TProvider.ServiceKey(type, stdAlg, true);
            TProvider.Service s = legacyMap.get(key);
            if (s == null) {
                s = new TProvider.Service(this);
                s.type = type;
                s.algorithm = stdAlg;
                legacyMap.put(key, s);
            }
            legacyMap.put(new TProvider.ServiceKey(type, aliasAlg, true), s);
            s.addAlias(aliasAlg);
        } else {
            String[] typeAndAlg = getTypeAndAlgorithm(name);
            if (typeAndAlg == null) {
                return;
            }
            int i = typeAndAlg[1].indexOf(' ');
            if (i == -1) {
                // e.g. put("MessageDigest.SHA-1", "sun.security.provider.SHA");
                String type = getEngineName(typeAndAlg[0]);
                String stdAlg = typeAndAlg[1].intern();
                String className = value;
                TProvider.ServiceKey key = new TProvider.ServiceKey(type, stdAlg, true);
                TProvider.Service s = legacyMap.get(key);
                if (s == null) {
                    s = new TProvider.Service(this);
                    s.type = type;
                    s.algorithm = stdAlg;
                    legacyMap.put(key, s);
                }
                s.className = className;
            } else { // attribute
                // e.g. put("MessageDigest.SHA-1 ImplementedIn", "Software");
                String attributeValue = value;
                String type = getEngineName(typeAndAlg[0]);
                String attributeString = typeAndAlg[1];
                String stdAlg = attributeString.substring(0, i).intern();
                String attributeName = attributeString.substring(i + 1);
                // kill additional spaces
                while (attributeName.startsWith(" ")) {
                    attributeName = attributeName.substring(1);
                }
                attributeName = attributeName.intern();
                TProvider.ServiceKey key = new TProvider.ServiceKey(type, stdAlg, true);
                TProvider.Service s = legacyMap.get(key);
                if (s == null) {
                    s = new TProvider.Service(this);
                    s.type = type;
                    s.algorithm = stdAlg;
                    legacyMap.put(key, s);
                }
                s.addAttribute(attributeName, attributeValue);
            }
        }
    }

    private void removeInvalidServices(Map<TProvider.ServiceKey, TProvider.Service> map) {
        for (Iterator<Map.Entry<ServiceKey, Service>> t =
             map.entrySet().iterator(); t.hasNext(); ) {
            TProvider.Service s = t.next().getValue();
            if (s.isValid() == false) {
                t.remove();
            }
        }
    }

    private void ensureLegacyParsed() {
        if ((legacyChanged == false) || (legacyStrings == null)) {
            return;
        }
        serviceSet = null;
        if (legacyMap == null) {
            legacyMap = new LinkedHashMap<ServiceKey, Service>();
        } else {
            legacyMap.clear();
        }
        for (Map.Entry<String,String> entry : legacyStrings.entrySet()) {
            parseLegacyPut(entry.getKey(), entry.getValue());
        }
        removeInvalidServices(legacyMap);
        legacyChanged = false;
    }

    public synchronized TProvider.Service getService(String type, String algorithm) {
        checkInitialized();
        // avoid allocating a new key object if possible
        TProvider.ServiceKey key = previousKey;
        if (!key.matches(type, algorithm)) {
            key = new TProvider.ServiceKey(type, algorithm, false);
            previousKey = key;
        }
        if (serviceMap != null) {
            TProvider.Service service = serviceMap.get(key);
            if (service != null) {
                return service;
            }
        }
        ensureLegacyParsed();
        return (legacyMap != null) ? legacyMap.get(key) : null;
    }

    private static class UString {
        final String string;
        final String lowerString;

        UString(String s) {
            this.string = s;
            this.lowerString = s.toLowerCase(ENGLISH);
        }

        public int hashCode() {
            return lowerString.hashCode();
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof TProvider.UString)) {
                return false;
            }
            TProvider.UString other = (TProvider.UString)obj;
            return lowerString.equals(other.lowerString);
        }

        public String toString() {
            return string;
        }
    }

    private static class EngineDescription {
        final String name;
        final boolean supportsParameter;
        final String constructorParameterClassName;
        private volatile Class<?> constructorParameterClass;

        EngineDescription(String name, boolean sp, String paramName) {
            this.name = name;
            this.supportsParameter = sp;
            this.constructorParameterClassName = paramName;
        }
        Class<?> getConstructorParameterClass() throws ClassNotFoundException {
            Class<?> clazz = constructorParameterClass;
            if (clazz == null) {
                clazz = Class.forName(constructorParameterClassName);
                constructorParameterClass = clazz;
            }
            return clazz;
        }
    }

    private static final Map<String, TProvider.EngineDescription> knownEngines;

    private static void addEngine(String name, boolean sp, String paramName) {
        TProvider.EngineDescription ed = new TProvider.EngineDescription(name, sp, paramName);
        // also index by canonical name to avoid toLowerCase() for some lookups
        knownEngines.put(name.toLowerCase(ENGLISH), ed);
        knownEngines.put(name, ed);
    }

    static {
        knownEngines = new HashMap<String, TProvider.EngineDescription>();
        // JCA
        addEngine("AlgorithmParameterGenerator",        false, null);
        addEngine("AlgorithmParameters",                false, null);
        addEngine("KeyFactory",                         false, null);
        addEngine("KeyPairGenerator",                   false, null);
        addEngine("KeyStore",                           false, null);
        addEngine("MessageDigest",                      false, null);
        addEngine("SecureRandom",                       false, null);
        addEngine("Signature",                          true,  null);
        addEngine("CertificateFactory",                 false, null);
        addEngine("CertPathBuilder",                    false, null);
        addEngine("CertPathValidator",                  false, null);
        addEngine("CertStore",                          false,
                "java.security.cert.CertStoreParameters");
        // JCE
        addEngine("Cipher",                             true,  null);
        addEngine("ExemptionMechanism",                 false, null);
        addEngine("Mac",                                true,  null);
        addEngine("KeyAgreement",                       true,  null);
        addEngine("KeyGenerator",                       false, null);
        addEngine("SecretKeyFactory",                   false, null);
        // JSSE
        addEngine("KeyManagerFactory",                  false, null);
        addEngine("SSLContext",                         false, null);
        addEngine("TrustManagerFactory",                false, null);
        // JGSS
        addEngine("GssApiMechanism",                    false, null);
        // SASL
        addEngine("SaslClientFactory",                  false, null);
        addEngine("SaslServerFactory",                  false, null);
        // POLICY
        addEngine("Policy",                             false,
                "java.security.Policy$Parameters");
        // CONFIGURATION
        addEngine("Configuration",                      false,
                "javax.security.auth.login.Configuration$Parameters");
        // XML DSig
        addEngine("XMLSignatureFactory",                false, null);
        addEngine("KeyInfoFactory",                     false, null);
        addEngine("TransformService",                   false, null);
        // Smart Card I/O
        addEngine("TerminalFactory",                    false,
                "java.lang.Object");
    }

    private static String getEngineName(String s) {
        // try original case first, usually correct
        TProvider.EngineDescription e = knownEngines.get(s);
        if (e == null) {
            e = knownEngines.get(s.toLowerCase(ENGLISH));
        }
        return (e == null) ? s : e.name;
    }

    public static class Service {

        private String type;
        private String algorithm;
        private String className;
        private final TProvider provider;
        private List<String> aliases;
        private Map<UString, String> attributes;

        // Reference to the cached implementation Class object
        private volatile Reference<Class<?>> classRef;

        // flag indicating whether this service has its attributes for
        // supportedKeyFormats or supportedKeyClasses set
        // if null, the values have not been initialized
        // if TRUE, at least one of supportedFormats/Classes is non null
        private volatile Boolean hasKeyAttributes;

        // supported encoding formats
        private String[] supportedFormats;

        // names of the supported key (super) classes
        private Class[] supportedClasses;

        // whether this service has been registered with the Provider
        private boolean registered;

        private static final Class<?>[] CLASS0 = new Class<?>[0];

        // this constructor and these methods are used for parsing
        // the legacy string properties.

        private Service(TProvider provider) {
            this.provider = provider;
            aliases = Collections.<String>emptyList();
            attributes = Collections.<TProvider.UString, String>emptyMap();
        }

        private boolean isValid() {
            return (type != null) && (algorithm != null) && (className != null);
        }

        private void addAlias(String alias) {
            if (aliases.isEmpty()) {
                aliases = new ArrayList<String>(2);
            }
            aliases.add(alias);
        }

        void addAttribute(String type, String value) {
            if (attributes.isEmpty()) {
                attributes = new HashMap<UString, String>(8);
            }
            attributes.put(new TProvider.UString(type), value);
        }

        /**
         * Construct a new service.
         *
         * @param provider   the provider that offers this service
         * @param type       the type of this service
         * @param algorithm  the algorithm name
         * @param className  the name of the class implementing this service
         * @param aliases    List of aliases or null if algorithm has no aliases
         * @param attributes Map of attributes or null if this implementation
         *                   has no attributes
         * @throws NullPointerException if provider, type, algorithm, or
         *                              className is null
         */
        public Service(TProvider provider, String type, String algorithm,
                String className, List<String> aliases,
                Map<String, String> attributes) {
            if ((provider == null) || (type == null) ||
                    (algorithm == null) || (className == null)) {
                throw new NullPointerException();
            }
            this.provider = provider;
            this.type = getEngineName(type);
            this.algorithm = algorithm;
            this.className = className;
            if (aliases == null) {
                this.aliases = Collections.<String>emptyList();
            } else {
                this.aliases = new ArrayList<String>(aliases);
            }
            if (attributes == null) {
                this.attributes = Collections.<TProvider.UString, String>emptyMap();
            } else {
                this.attributes = new HashMap<TProvider.UString, String>();
                for (Map.Entry<String, String> entry : attributes.entrySet()) {
                    this.attributes.put(new TProvider.UString(entry.getKey()), entry.getValue());
                }
            }
        }
    }
}
