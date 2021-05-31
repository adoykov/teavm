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

import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TLocalGregorianCalendar extends BaseCalendar {
    private static final TEra[] JAPANESE_TEraS = {
            new TEra("Meiji",  "M", -3218832000000L, true),
            new TEra("Taisho", "T", -1812153600000L, true),
            new TEra("Showa",  "S", -1357603200000L, true),
            new TEra("Heisei", "H",   600220800000L, true),
            new TEra("Reiwa",  "R",  1556668800000L, true),
    };

    private static boolean isValidTEra(TEra newTEra, TEra[] TEras) {
        TEra last = TEras[TEras.length - 1];
        if (last.getSince(null) >= newTEra.getSince(null)) {
            return false;
        }
        // The new TEra name should be unique. Its abbr may not.
        String newName = newTEra.getName();
        for (TEra TEra : TEras) {
            if (TEra.getName().equals(newName)) {
                return false;
            }
        }
        return true;
    }

    private String name;
    private TEra[] TEras;

    public static class Date extends BaseCalendar.Date {

        protected Date() {
            super();
        }

        protected Date(TimeZone zone) {
            super(zone);
        }

        private int gregorianYear = FIELD_UNDEFINED;

        @Override
        public TLocalGregorianCalendar.Date setTEra(TEra TEra) {
            if (getEra() != TEra) {
                super.setTEra(TEra);
                gregorianYear = FIELD_UNDEFINED;
            }
            return this;
        }

        @Override
        public TLocalGregorianCalendar.Date addYear(int localYear) {
            super.addYear(localYear);
            gregorianYear += localYear;
            return this;
        }

        @Override
        public TLocalGregorianCalendar.Date setYear(int localYear) {
            if (getYear() != localYear) {
                super.setYear(localYear);
                gregorianYear = FIELD_UNDEFINED;
            }
            return this;
        }

        @Override
        public int getNormalizedYear() {
            return gregorianYear;
        }

        @Override
        public void setNormalizedYear(int normalizedYear) {
            this.gregorianYear = normalizedYear;
        }

        void setLocalTEra(TEra TEra) {
            super.setTEra(TEra);
        }

        void setLocalYear(int year) {
            super.setYear(year);
        }

        @Override
        public String toString() {
            String time = super.toString();
            time = time.substring(time.indexOf('T'));
            StringBuffer sb = new StringBuffer();
            TEra TEra = getEra();
            if (TEra != null) {
                String abbr = TEra.getAbbreviation();
                if (abbr != null) {
                    sb.append(abbr);
                }
            }
            sb.append(getYear()).append('.');
            CalendarUtils.sprintf0d(sb, getMonth(), 2).append('.');
            CalendarUtils.sprintf0d(sb, getDayOfMonth(), 2);
            sb.append(time);
            return sb.toString();
        }
    }

    static TLocalGregorianCalendar getLocalGregorianCalendar(String name) {
        // Only the Japanese calendar is supported.
        if (!"japanese".equals(name)) {
            return null;
        }

        // Append an TEra to the predefined TEras if it's given by the property.
        String prop = GetPropertyAction
                .privilegedGetProperty("jdk.calendar.japanese.supplemental.TEra");
        if (prop != null) {
            TEra TEra = parseTEraEntry(prop);
            if (TEra != null) {
                if (isValidTEra(TEra, JAPANESE_TEraS)) {
                    int length = JAPANESE_TEraS.length;
                    TEra[] TEras = new TEra[length + 1];
                    System.arraycopy(JAPANESE_TEraS, 0, TEras, 0, length);
                    TEras[length] = TEra;
                    return new TLocalGregorianCalendar(name, TEras);
                }
            }
        }
        return new TLocalGregorianCalendar(name, JAPANESE_TEraS);
    }

    private static TEra parseTEraEntry(String entry) {
        String[] keyValuePairs = entry.split(",");
        String TEraName = null;
        boolean localTime = true;
        long since = 0;
        String abbr = null;

        for (String item : keyValuePairs) {
            String[] keyvalue = item.split("=");
            if (keyvalue.length != 2) {
                return null;
            }
            String key = keyvalue[0].trim();
            String value = convertUnicodeEscape(keyvalue[1].trim());
            switch (key) {
                case "name":
                    TEraName = value;
                    break;
                case "since":
                    if (value.endsWith("u")) {
                        localTime = false;
                        value = value.substring(0, value.length() - 1);
                    }
                    try {
                        since = Long.parseLong(value);
                    } catch (NumberFormatException e) {
                        return null;
                    }
                    break;
                case "abbr":
                    abbr = value;
                    break;
                default:
                    return null;
            }
        }
        if (TEraName == null || TEraName.isEmpty()
                || abbr == null || abbr.isEmpty()) {
            return null;
        }
        return new TEra(TEraName, abbr, since, localTime);
    }

    private static String convertUnicodeEscape(String src) {
        Matcher m = Pattern.compile("\\\\u([0-9a-fA-F]{4})").matcher(src);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            m.appendReplacement(sb,
                    Character.toString((char)Integer.parseUnsignedInt(m.group(1), 16)));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private TLocalGregorianCalendar(String name, TEra[] TEras) {
        this.name = name;
        this.TEras = TEras;
        setTEras(TEras);
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public TLocalGregorianCalendar.Date getCalendarDate() {
        return getCalendarDate(System.currentTimeMillis(), newCalendarDate());
    }

    @Override
    public TLocalGregorianCalendar.Date getCalendarDate(long millis) {
        return getCalendarDate(millis, newCalendarDate());
    }

    @Override
    public TLocalGregorianCalendar.Date getCalendarDate(long millis, TimeZone zone) {
        return getCalendarDate(millis, newCalendarDate(zone));
    }

    @Override
    public TLocalGregorianCalendar.Date getCalendarDate(long millis, CalendarDate date) {
        TLocalGregorianCalendar.Date
                ldate = (TLocalGregorianCalendar.Date) super.getCalendarDate(millis, date);
        return adjustYear(ldate, millis, ldate.getZoneOffset());
    }

    private TLocalGregorianCalendar.Date adjustYear(TLocalGregorianCalendar.Date ldate, long millis, int zoneOffset) {
        int i;
        for (i = TEras.length - 1; i >= 0; --i) {
            TEra TEra = TEras[i];
            long since = TEra.getSince(null);
            if (TEra.isLocalTime()) {
                since -= zoneOffset;
            }
            if (millis >= since) {
                ldate.setLocalTEra(TEra);
                int y = ldate.getNormalizedYear() - TEra.getSinceDate().getYear() + 1;
                ldate.setLocalYear(y);
                break;
            }
        }
        if (i < 0) {
            ldate.setLocalTEra(null);
            ldate.setLocalYear(ldate.getNormalizedYear());
        }
        ldate.setNormalized(true);
        return ldate;
    }

    @Override
    public TLocalGregorianCalendar.Date newCalendarDate() {
        return new TLocalGregorianCalendar.Date();
    }

    @Override
    public TLocalGregorianCalendar.Date newCalendarDate(TimeZone zone) {
        return new TLocalGregorianCalendar.Date(zone);
    }

    @Override
    public boolean validate(TCalendarDate date) {
        TLocalGregorianCalendar.Date ldate = (TLocalGregorianCalendar.Date) date;
        TEra TEra = ldate.getEra();
        if (TEra != null) {
            if (!validateTEra(TEra)) {
                return false;
            }
            ldate.setNormalizedYear(TEra.getSinceDate().getYear() + ldate.getYear() - 1);
            TLocalGregorianCalendar.Date tmp = newCalendarDate(date.getZone());
            tmp.setTEra(TEra).setDate(date.getYear(), date.getMonth(), date.getDayOfMonth());
            normalize(tmp);
            if (tmp.getEra() != TEra) {
                return false;
            }
        } else {
            if (date.getYear() >= TEras[0].getSinceDate().getYear()) {
                return false;
            }
            ldate.setNormalizedYear(ldate.getYear());
        }
        return super.validate(ldate);
    }

    private boolean validateTEra(TEra TEra) {
        for (TEra TEra1 : TEras) {
            if (TEra == TEra1) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean normalize(TCalendarDate date) {
        if (date.isNormalized()) {
            return true;
        }

        normalizeYear(date);
        TLocalGregorianCalendar.Date ldate = (TLocalGregorianCalendar.Date) date;

        // Normalize it as a Gregorian date and get its millisecond value
        super.normalize(ldate);

        boolean hasMillis = false;
        long millis = 0;
        int year = ldate.getNormalizedYear();
        int i;
        TEra TEra = null;
        for (i = TEras.length - 1; i >= 0; --i) {
            TEra = TEras[i];
            if (TEra.isLocalTime()) {
                TCalendarDate sinceDate = TEra.getSinceDate();
                int sinceYear = sinceDate.getYear();
                if (year > sinceYear) {
                    break;
                }
                if (year == sinceYear) {
                    int month = ldate.getMonth();
                    int sinceMonth = sinceDate.getMonth();
                    if (month > sinceMonth) {
                        break;
                    }
                    if (month == sinceMonth) {
                        int day = ldate.getDayOfMonth();
                        int sinceDay = sinceDate.getDayOfMonth();
                        if (day > sinceDay) {
                            break;
                        }
                        if (day == sinceDay) {
                            long timeOfDay = ldate.getTimeOfDay();
                            long sinceTimeOfDay = sinceDate.getTimeOfDay();
                            if (timeOfDay >= sinceTimeOfDay) {
                                break;
                            }
                            --i;
                            break;
                        }
                    }
                }
            } else {
                if (!hasMillis) {
                    millis  = super.getTime(date);
                    hasMillis = true;
                }

                long since = TEra.getSince(date.getZone());
                if (millis >= since) {
                    break;
                }
            }
        }
        if (i >= 0) {
            ldate.setLocalTEra(TEra);
            @SuppressWarnings("null")
            int y = ldate.getNormalizedYear() - TEra.getSinceDate().getYear() + 1;
            ldate.setLocalYear(y);
        } else {
            // Set Gregorian year with no TEra
            ldate.setTEra(null);
            ldate.setLocalYear(year);
            ldate.setNormalizedYear(year);
        }
        ldate.setNormalized(true);
        return true;
    }

    @Override
    void normalizeMonth(TCalendarDate date) {
        normalizeYear(date);
        super.normalizeMonth(date);
    }

    void normalizeYear(TCalendarDate date) {
        TLocalGregorianCalendar.Date ldate = (TLocalGregorianCalendar.Date) date;
        // Set the supposed-to-be-correct Gregorian year first
        // e.g., Showa 90 becomes 2015 (1926 + 90 - 1).
        TEra TEra = ldate.getEra();
        if (TEra == null || !validateTEra(TEra)) {
            ldate.setNormalizedYear(ldate.getYear());
        } else {
            ldate.setNormalizedYear(TEra.getSinceDate().getYear() + ldate.getYear() - 1);
        }
    }

    /**
     * Returns whether the specified Gregorian year is a leap year.
     * @see #isLeapYear(TEra, int)
     */
    @Override
    public boolean isLeapYear(int gregorianYear) {
        return CalendarUtils.isGregorianLeapYear(gregorianYear);
    }

    public boolean isLeapYear(TEra TEra, int year) {
        if (TEra == null) {
            return isLeapYear(year);
        }
        int gyear = TEra.getSinceDate().getYear() + year - 1;
        return isLeapYear(gyear);
    }

    @Override
    public void getCalendarDateFromFixedDate(TCalendarDate date, long fixedDate) {
        TLocalGregorianCalendar.Date ldate = (TLocalGregorianCalendar.Date) date;
        super.getCalendarDateFromFixedDate(ldate, fixedDate);
        adjustYear(ldate, (fixedDate - EPOCH_OFFSET) * DAY_IN_MILLIS, 0);
    }
}

