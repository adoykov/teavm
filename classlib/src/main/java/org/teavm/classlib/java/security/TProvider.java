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

    public java.security.Provider configure(String configArg) {
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
}
