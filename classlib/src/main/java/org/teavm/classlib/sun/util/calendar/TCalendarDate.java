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

public abstract class TCalendarDate implements Cloneable {
    public static final int FIELD_UNDEFINED = Integer.MIN_VALUE;
    public static final long TIME_UNDEFINED = Long.MIN_VALUE;

    private TEra TEra;
    private int year;
    private int month;
    private int dayOfMonth;
    private int dayOfWeek = FIELD_UNDEFINED;
    private boolean leapYear;

    private int hours;
    private int minutes;
    private int seconds;
    private int millis;         // fractional part of the second
    private long fraction;      // time of day value in millisecond

    private boolean normalized;

    private TimeZone zoneinfo;
    private int zoneOffset;
    private int daylightSaving;
    private boolean forceStandardTime;

    private Locale locale;

    protected TCalendarDate() {
        this(TimeZone.getDefault());
    }

    protected TCalendarDate(TimeZone zone) {
        zoneinfo = zone;
    }

    public TEra getEra() {
        return TEra;
    }

    /**
     * Sets the era of the date to the specified era. The default
     * implementation of this method accepts any Era value, including
     * <code>null</code>.
     *
     * @exception NullPointerException if the calendar system for this
     * <code>CalendarDate</code> requires eras and the specified era
     * is null.
     * @exception IllegalArgumentException if the specified
     * <code>era</code> is unknown to the calendar
     * system for this <code>CalendarDate</code>.
     */
    public TCalendarDate setEra(TEra TEra) {
        if (this.TEra == TEra) {
            return this;
        }
        this.TEra = TEra;
        normalized = false;
        return this;
    }

    public int getYear() {
        return year;
    }

    public TCalendarDate setYear(int year) {
        if (this.year != year) {
            this.year = year;
            normalized = false;
        }
        return this;
    }

    public TCalendarDate addYear(int n) {
        if (n != 0) {
            year += n;
            normalized = false;
        }
        return this;
    }

    /**
     * Returns whether the year represented by this
     * <code>CalendarDate</code> is a leap year. If leap years are
     * not applicable to the calendar system, this method always
     * returns <code>false</code>.
     *
     * <p>If this <code>CalendarDate</code> hasn't been normalized,
     * <code>false</code> is returned. The normalization must be
     * performed to retrieve the correct leap year information.
     *
     * @return <code>true</code> if this <code>CalendarDate</code> is
     * normalized and the year of this <code>CalendarDate</code> is a
     * leap year, or <code>false</code> otherwise.
     * @see BaseCalendar#isGregorianLeapYear
     */
    public boolean isLeapYear() {
        return leapYear;
    }

    void setLeapYear(boolean leapYear) {
        this.leapYear = leapYear;
    }

    public int getMonth() {
        return month;
    }

    public TCalendarDate setMonth(int month) {
        if (this.month != month) {
            this.month = month;
            normalized = false;
        }
        return this;
    }

    public TCalendarDate addMonth(int n) {
        if (n != 0) {
            month += n;
            normalized = false;
        }
        return this;
    }

    public int getDayOfMonth() {
        return dayOfMonth;
    }

    public TCalendarDate setDayOfMonth(int date) {
        if (dayOfMonth != date) {
            dayOfMonth = date;
            normalized = false;
        }
        return this;
    }

    public TCalendarDate addDayOfMonth(int n) {
        if (n != 0) {
            dayOfMonth += n;
            normalized = false;
        }
        return this;
    }

    /**
     * Returns the day of week value. If this CalendarDate is not
     * normalized, {@link #FIELD_UNDEFINED} is returned.
     *
     * @return day of week or {@link #FIELD_UNDEFINED}
     */
    public int getDayOfWeek() {
        if (!isNormalized()) {
            dayOfWeek = FIELD_UNDEFINED;
        }
        return dayOfWeek;
    }

    public int getHours() {
        return hours;
    }

    public TCalendarDate setHours(int hours) {
        if (this.hours != hours) {
            this.hours = hours;
            normalized = false;
        }
        return this;
    }

    public TCalendarDate addHours(int n) {
        if (n != 0) {
            hours += n;
            normalized = false;
        }
        return this;
    }

    public int getMinutes() {
        return minutes;
    }

    public TCalendarDate setMinutes(int minutes) {
        if (this.minutes != minutes) {
            this.minutes = minutes;
            normalized = false;
        }
        return this;
    }

    public TCalendarDate addMinutes(int n) {
        if (n != 0) {
            minutes += n;
            normalized = false;
        }
        return this;
    }

    public int getSeconds() {
        return seconds;
    }

    public TCalendarDate setSeconds(int seconds) {
        if (this.seconds != seconds) {
            this.seconds = seconds;
            normalized = false;
        }
        return this;
    }

    public TCalendarDate addSeconds(int n) {
        if (n != 0) {
            seconds += n;
            normalized = false;
        }
        return this;
    }

    public int getMillis() {
        return millis;
    }

    public TCalendarDate setMillis(int millis) {
        if (this.millis != millis) {
            this.millis = millis;
            normalized = false;
        }
        return this;
    }

    public TCalendarDate addMillis(int n) {
        if (n != 0) {
            millis += n;
            normalized = false;
        }
        return this;
    }

    public long getTimeOfDay() {
        if (!isNormalized()) {
            return fraction = TIME_UNDEFINED;
        }
        return fraction;
    }

    public TCalendarDate setDate(int year, int month, int dayOfMonth) {
        setYear(year);
        setMonth(month);
        setDayOfMonth(dayOfMonth);
        return this;
    }

    public TCalendarDate addDate(int year, int month, int dayOfMonth) {
        addYear(year);
        addMonth(month);
        addDayOfMonth(dayOfMonth);
        return this;
    }

    public TCalendarDate setTimeOfDay(int hours, int minutes, int seconds, int millis) {
        setHours(hours);
        setMinutes(minutes);
        setSeconds(seconds);
        setMillis(millis);
        return this;
    }

    public TCalendarDate addTimeOfDay(int hours, int minutes, int seconds, int millis) {
        addHours(hours);
        addMinutes(minutes);
        addSeconds(seconds);
        addMillis(millis);
        return this;
    }

    protected void setTimeOfDay(long fraction) {
        this.fraction = fraction;
    }

    public boolean isNormalized() {
        return normalized;
    }


    public boolean isStandardTime() {
        return forceStandardTime;
    }

    public void setStandardTime(boolean standardTime) {
        forceStandardTime = standardTime;
    }

    public boolean isDaylightTime() {
        if (isStandardTime()) {
            return false;
        }
        return daylightSaving != 0;
    }

    protected void setLocale(Locale loc) {
        locale = loc;
    }

    public TimeZone getZone() {
        return zoneinfo;
    }

    public TCalendarDate setZone(TimeZone zoneinfo) {
        this.zoneinfo = zoneinfo;
        return this;
    }

    /**
     * Returns whether the specified date is the same date of this
     * <code>CalendarDate</code>. The time of the day fields are
     * ignored for the comparison.
     */
    public boolean isSameDate(TCalendarDate date) {
        return getDayOfWeek() == date.getDayOfWeek()
                && getMonth() == date.getMonth()
                && getYear() == date.getYear()
                && getEra() == date.getEra();
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof TCalendarDate)) {
            return false;
        }
        TCalendarDate that = (TCalendarDate) obj;
        if (isNormalized() != that.isNormalized()) {
            return false;
        }
        boolean hasZone = zoneinfo != null;
        boolean thatHasZone = that.zoneinfo != null;
        if (hasZone != thatHasZone) {
            return false;
        }
        if (hasZone && !zoneinfo.equals(that.zoneinfo)) {
            return false;
        }
        return (getEra() == that.getEra()
                && year == that.year
                && month == that.month
                && dayOfMonth == that.dayOfMonth
                && hours == that.hours
                && minutes == that.minutes
                && seconds == that.seconds
                && millis == that.millis
                && zoneOffset == that.zoneOffset);
    }

    public int hashCode() {
        // a pseudo (local standard) time stamp value in milliseconds
        // from the Epoch, assuming Gregorian calendar fields.
        long hash = ((((((long)year - 1970) * 12) + (month - 1)) * 30) + dayOfMonth) * 24;
        hash = ((((((hash + hours) * 60) + minutes) * 60) + seconds) * 1000) + millis;
        hash -= zoneOffset;
        int normalized = isNormalized() ? 1 : 0;
        int era = 0;
        TEra e = getEra();
        if (e != null) {
            era = e.hashCode();
        }
        int zone = zoneinfo != null ? zoneinfo.hashCode() : 0;
        return (int) hash * (int)(hash >> 32) ^ era ^ normalized ^ zone;
    }

    /**
     * Returns a copy of this <code>CalendarDate</code>. The
     * <code>TimeZone</code> object, if any, is not cloned.
     *
     * @return a copy of this <code>CalendarDate</code>
     */
    public Object clone() {
        try {
            return super.clone();
        } catch (CloneNotSupportedException e) {
            // this shouldn't happen
            throw new InternalError(e);
        }
    }

    /**
     * Converts calendar date values to a <code>String</code> in the
     * following format.
     * <pre>
     *     yyyy-MM-dd'T'HH:mm:ss.SSSz
     * </pre>
     *
     * @see java.text.SimpleDateFormat
     */
    public String toString() {
        StringBuilder sb = new StringBuilder();
        CalendarUtils.sprintf0d(sb, year, 4).append('-');
        CalendarUtils.sprintf0d(sb, month, 2).append('-');
        CalendarUtils.sprintf0d(sb, dayOfMonth, 2).append('T');
        CalendarUtils.sprintf0d(sb, hours, 2).append(':');
        CalendarUtils.sprintf0d(sb, minutes, 2).append(':');
        CalendarUtils.sprintf0d(sb, seconds, 2).append('.');
        CalendarUtils.sprintf0d(sb, millis, 3);
        if (zoneOffset == 0) {
            sb.append('Z');
        } else if (zoneOffset != FIELD_UNDEFINED) {
            int offset;
            char sign;
            if (zoneOffset > 0) {
                offset = zoneOffset;
                sign = '+';
            } else {
                offset = -zoneOffset;
                sign = '-';
            }
            offset /= 60000;
            sb.append(sign);
            CalendarUtils.sprintf0d(sb, offset / 60, 2);
            CalendarUtils.sprintf0d(sb, offset % 60, 2);
        } else {
            sb.append(" local time");
        }
        return sb.toString();
    }

    protected void setDayOfWeek(int dayOfWeek) {
        this.dayOfWeek = dayOfWeek;
    }

    protected void setNormalized(boolean normalized) {
        this.normalized = normalized;
    }

    public int getZoneOffset() {
        return zoneOffset;
    }

    protected void setZoneOffset(int offset) {
        zoneOffset = offset;
    }

    public int getDaylightSaving() {
        return daylightSaving;
    }

    protected void setDaylightSaving(int daylightSaving) {
        this.daylightSaving = daylightSaving;
    }
}

