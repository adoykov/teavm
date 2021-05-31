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
package org.teavm.classlib.sun.util.calendar;

import java.util.Locale;
import java.util.TimeZone;

public final class TEra {
    private final String name;
    private final String abbr;
    private final long since;
    private final TCalendarDate sinceDate;
    private final boolean localTime;

    /**
     * Constructs an <code>Era</code> instance.
     *
     * @param name the era name (e.g., "BeforeCommonEra" for the Julian calendar system)
     * @param abbr the abbreviation of the era name (e.g., "B.C.E." for "BeforeCommonEra")
     * @param since the time (millisecond offset from January 1, 1970
     * (Gregorian) UTC or local time) when the era starts, inclusive.
     * @param localTime <code>true</code> if <code>since</code>
     * specifies a local time; <code>false</code> if
     * <code>since</code> specifies UTC
     */
    public TEra(String name, String abbr, long since, boolean localTime) {
        this.name = name;
        this.abbr = abbr;
        this.since = since;
        this.localTime = localTime;
        Gregorian gcal = CalendarSystem.getGregorianCalendar();
        BaseCalendar.Date d = (BaseCalendar.Date) gcal.newCalendarDate(null);
        gcal.getCalendarDate(since, d);
        sinceDate = new ImmutableGregorianDate(d);
    }

    public String getName() {
        return name;
    }

    public String getDisplayName(Locale locale) {
        return name;
    }

    public String getAbbreviation() {
        return abbr;
    }

    public String getDiaplayAbbreviation(Locale locale) {
        return abbr;
    }

    public long getSince(TimeZone zone) {
        if (zone == null || !localTime) {
            return since;
        }
        int offset = zone.getOffset(since);
        return since - offset;
    }

    public CalendarDate getSinceDate() {
        return sinceDate;
    }

    public boolean isLocalTime() {
        return localTime;
    }

    public boolean equals(Object o) {
        if (!(o instanceof TEra)) {
            return false;
        }
        TEra that = (TEra) o;
        return name.equals(that.name)
                && abbr.equals(that.abbr)
                && since == that.since
                && localTime == that.localTime;
    }

    private int hash = 0;

    public int hashCode() {
        if (hash == 0) {
            hash = name.hashCode() ^ abbr.hashCode() ^ (int)since ^ (int)(since >> 32)
                    ^ (localTime ? 1 : 0);
        }
        return hash;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append('[');
        sb.append(getName()).append(" (");
        sb.append(getAbbreviation()).append(')');
        sb.append(" since ").append(getSinceDate());
        if (localTime) {
            sb.setLength(sb.length() - 1); // remove 'Z'
            sb.append(" local time");
        }
        sb.append(']');
        return sb.toString();
    }
}

