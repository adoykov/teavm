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
package org.teavm.classlib.java.time;

import org.teavm.classlib.java.lang.TMath;

public final class TInstant implements Comparable<TInstant> {
    public static final TInstant EPOCH = new TInstant(0, 0);
    private static final long MIN_SECOND = -31557014167219200L;
    private static final long MAX_SECOND = 31556889864403199L;
    public static final TInstant MIN = TInstant.ofEpochSecond(MIN_SECOND, 0);
    public static final TInstant MAX = TInstant.ofEpochSecond(MAX_SECOND, 999_999_999);
    private final long seconds;
    private final int nanos;

    // TODO: This is in the wrong place, should be in LocalTime
    static final long NANOS_PER_SECOND =  1000_000_000L;

    public static TInstant now() {
        return EPOCH;
    }

//    public static TInstant now(TClock clock) {
//        return clock.instant();
//    }

    public static TInstant ofEpochSecond(long epochSecond) {
        return new TInstant(epochSecond, 0);
    }

    public static TInstant ofEpochSecond(long epochSecond, long nanoAdjustment) {
        long secs = epochSecond + TMath.floorDiv(nanoAdjustment, NANOS_PER_SECOND);
        int nanosOfSecond = (int) TMath.floorMod(nanoAdjustment, NANOS_PER_SECOND);
        return new TInstant(secs, nanosOfSecond);
    }

    public static TInstant ofEpochMilli(long epochMilli) {
        long secs = TMath.floorDiv(epochMilli, 1000);
        int nanosOfSecond = TMath.floorMod(epochMilli, 1000) * 1000_000;
        return new TInstant(secs, nanosOfSecond);
    }

    private TInstant(long epochSecond, int nanos) {
        if (epochSecond < MIN_SECOND || epochSecond > MAX_SECOND) {
            throw new TDateTimeException("Instant exceeds minimum or maximum instant");
        }
        this.seconds = epochSecond;
        this.nanos = nanos;
    }

    public long getEpochSecond() {
        return seconds;
    }

    public int getNano() {
        return nanos;
    }

    public long toEpochMilli() {
        if (seconds < 0 && nanos > 0) {
            long millis = (seconds + 1) * 1000;
            long adjustment = nanos / 1000_000 - 1000;
            return millis + adjustment;
        } else {
            long millis = seconds * 1000;
            return millis + (nanos / 1000_000);
        }
    }

    @Override
    public int compareTo(TInstant otherInstant) {
        int cmp = Long.compare(seconds, otherInstant.seconds);
        if (cmp != 0) {
            return cmp;
        }
        return nanos - otherInstant.nanos;
    }

    public boolean isAfter(TInstant otherInstant) {
        return compareTo(otherInstant) > 0;
    }

    public boolean isBefore(TInstant otherInstant) {
        return compareTo(otherInstant) < 0;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof TInstant)) {
            return false;
        }
        TInstant other = (TInstant) obj;
        return this.seconds == other.seconds && this.nanos == other.nanos;
    }

    @Override
    public int hashCode() {
        return ((int) (seconds ^ (seconds >>> 32))) + 51 * nanos;
    }

}
