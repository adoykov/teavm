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

public class TGregorian extends BaseCalendar {

    static class Date extends BaseCalendar.Date {
        protected Date() {
            super();
        }

        protected Date(TimeZone zone) {
            super(zone);
        }

        public int getNormalizedYear() {
            return getYear();
        }

        public void setNormalizedYear(int normalizedYear) {
            setYear(normalizedYear);
        }
    }

    TGregorian() {
    }

    public String getName() {
        return "gregorian";
    }

    public TGregorian.Date getCalendarDate() {
        return getCalendarDate(System.currentTimeMillis(), newCalendarDate());
    }

    public TGregorian.Date getCalendarDate(long millis) {
        return getCalendarDate(millis, newCalendarDate());
    }

    public TGregorian.Date getCalendarDate(long millis, CalendarDate date) {
        return (TGregorian.Date) super.getCalendarDate(millis, date);
    }

    public TGregorian.Date getCalendarDate(long millis, TimeZone zone) {
        return getCalendarDate(millis, newCalendarDate(zone));
    }

    public TGregorian.Date newCalendarDate() {
        return new TGregorian.Date();
    }

    public TGregorian.Date newCalendarDate(TimeZone zone) {
        return new TGregorian.Date(zone);
    }
}

