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

import sun.security.jca.Providers;

public class TProviders {

    private static volatile TProviderList providerList;
    private static TProviderList getSystemProviderList() {
        return providerList;
    }
    private static volatile int threadListsUsed;
    private static final ThreadLocal<TProviderList> threadLists =
            new InheritableThreadLocal<>();

    private static void changeThreadProviderList(TProviderList list) {
        threadLists.set(list);
    }
    private static void setSystemProviderList(TProviderList list) {
        providerList = list;
    }

    public static void setProviderList(TProviderList newList) {
        if (getThreadProviderList() == null) {
            setSystemProviderList(newList);
        } else {
            changeThreadProviderList(newList);
        }
    }

    public static TProviderList getFullProviderList() {
        TProviderList list;
        synchronized (Providers.class) {
            list = getThreadProviderList();
            if (list != null) {
                TProviderList newList = list.removeInvalid();
                if (newList != list) {
                    changeThreadProviderList(newList);
                    list = newList;
                }
                return list;
            }
        }
        list = getSystemProviderList();
        TProviderList newList = list.removeInvalid();
        if (newList != list) {
            setSystemProviderList(newList);
            list = newList;
        }
        return list;
    }

    public static TProviderList getProviderList() {
        TProviderList list = getThreadProviderList();
        if (list == null) {
            list = getSystemProviderList();
        }
        return list;
    }

    public static TProviderList getThreadProviderList() {
        // avoid accessing the threadlocal if none are currently in use
        // (first use of ThreadLocal.get() for a Thread allocates a Map)
        if (threadListsUsed == 0) {
            return null;
        }
        return threadLists.get();
    }

}
