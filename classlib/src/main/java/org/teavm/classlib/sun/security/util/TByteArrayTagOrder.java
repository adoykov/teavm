/*
 *  Copyright 2021 alexander.
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
package org.teavm.classlib.sun.security.util;

import java.util.Comparator;

public class TByteArrayTagOrder implements Comparator<byte[]> {

    /**
     * Compare two byte arrays, by the order of their tags,
     * as defined in ITU-T X.680, sec. 6.4.  (First compare
     *  tag classes, then tag numbers, ignoring the constructivity bit.)
     *
     * @param  bytes1 first byte array to compare.
     * @param  bytes2 second byte array to compare.
     * @return negative number if {@code bytes1 < bytes2},
     *         0 if {@code bytes1 == bytes2},
     *         positive number if {@code bytes1 > bytes2}.
     *
     * @exception <code>ClassCastException</code>
     * if either argument is not a byte array.
     */

    public final int compare(byte[] bytes1, byte[] bytes2) {
        // tag order is same as byte order ignoring any difference in
        // the constructivity bit (0x02)
        return (bytes1[0] | 0x20) - (bytes2[0] | 0x20);
    }


}
