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

import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.teavm.classlib.java.security.TProvider;
import sun.security.jca.ProviderList;

public class TProviderList {

    private volatile boolean allLoaded;
    private final TProviderConfig[] configs;
    private final static TProviderConfig[] PC0 = new TProviderConfig[0];
    private final static TProvider[] P0 = new TProvider[0];

    public List<TProvider> providers() {
        return userList;
    }

    final static sun.security.util.Debug debug =
            sun.security.util.Debug.getInstance("jca", "ProviderList");

    public int getIndex(String name) {
        for (int i = 0; i < configs.length; i++) {
            TProvider p = getProvider(i);
            if (p.getName().equals(name)) {
                return i;
            }
        }
        return -1;
    }

    private int loadAll() {
        if (allLoaded) {
            return configs.length;
        }
        if (debug != null) {
            debug.println("Loading all providers");
            new Exception("Call trace").printStackTrace();
        }
        int n = 0;
        for (int i = 0; i < configs.length; i++) {
            TProvider p = configs[i].getProvider();
            if (p != null) {
                n++;
            }
        }
        if (n == configs.length) {
            allLoaded = true;
        }
        return n;
    }

    private static final TProvider EMPTY_PROVIDER =
            new TProvider("##Empty##", 1.0d, "initialization in progress") {
                private static final long serialVersionUID = 1151354171352296389L;
                // override getService() to return null slightly faster
                public Service getService(String type, String algorithm) {
                    return null;
                }
            };

    TProviderList removeInvalid() {
        int n = loadAll();
        if (n == configs.length) {
            return this;
        }
        TProviderConfig[] newConfigs = new TProviderConfig[n];
        for (int i = 0, j = 0; i < configs.length; i++) {
            TProviderConfig config = configs[i];
            if (config.isLoaded()) {
                newConfigs[j++] = config;
            }
        }
        return new TProviderList(newConfigs, true);
    }

    public static TProviderList insertAt(TProviderList providerList, TProvider p,
            int position) {
        if (providerList.getProvider(p.getName()) != null) {
            return providerList;
        }
        List<TProviderConfig> list = new ArrayList<>
                (Arrays.asList(providerList.configs));
        int n = list.size();
        if ((position < 0) || (position > n)) {
            position = n;
        }
        list.add(position, new TProviderConfig(p));
        return new TProviderList(list.toArray(PC0), true);
    }

    private TProviderConfig getProviderConfig(String name) {
        int index = getIndex(name);
        return (index != -1) ? configs[index] : null;
    }


    private TProviderList(TProviderConfig[] configs, boolean allLoaded) {
        this.configs = configs;
        this.allLoaded = allLoaded;
    }

    public TProvider getProvider(String name) {
        TProviderConfig config = getProviderConfig(name);
        return (config == null) ? null : config.getProvider();
    }

    TProvider getProvider(int index) {
        TProvider p = configs[index].getProvider();
        return (p != null) ? p : EMPTY_PROVIDER;
    }

    public int size() {
        return configs.length;
    }

    public static TProviderList remove(TProviderList providerList, String name) {
        // make sure provider exists
        if (providerList.getProvider(name) == null) {
            return providerList;
        }
        // copy all except matching to new list
        TProviderConfig[] configs = new TProviderConfig[providerList.size() - 1];
        int j = 0;
        for (TProviderConfig config : providerList.configs) {
            if (config.getProvider().getName().equals(name) == false) {
                configs[j++] = config;
            }
        }
        return new TProviderList(configs, true);
    }

    public TProvider[] toArray() {
        return providers().toArray(P0);
    }

    private final List<TProvider> userList = new AbstractList<TProvider>() {
        public int size() {
            return configs.length;
        }
        public TProvider get(int index) {
            return getProvider(index);
        }
    };
}
