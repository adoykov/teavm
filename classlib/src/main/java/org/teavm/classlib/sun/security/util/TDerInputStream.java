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

import java.io.InputStream;
import java.io.IOException;
import java.util.Date;
import java.util.Vector;
import java.math.BigInteger;
import java.io.DataInputStream;

/**
 * A DER input stream, used for parsing ASN.1 DER-encoded data such as
 * that found in X.509 certificates.  DER is a subset of BER/1, which has
 * the advantage that it allows only a single encoding of primitive data.
 * (High level data such as dates still support many encodings.)  That is,
 * it uses the "Definite" Encoding Rules (DER) not the "Basic" ones (BER).
 *
 * <P>Note that, like BER/1, DER streams are streams of explicitly
 * tagged data values.  Accordingly, this programming interface does
 * not expose any variant of the java.io.InputStream interface, since
 * that kind of input stream holds untagged data values and using that
 * I/O model could prevent correct parsing of the DER data.
 *
 * <P>At this time, this class supports only a subset of the types of DER
 * data encodings which are defined.  That subset is sufficient for parsing
 * most X.509 certificates.
 *
 *
 * @author David Brownell
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 */

public class TDerInputStream {

    /*
     * This version only supports fully buffered DER.  This is easy to
     * work with, though if large objects are manipulated DER becomes
     * awkward to deal with.  That's where BER is useful, since BER
     * handles streaming data relatively well.
     */
    TDerInputBuffer buffer;

    /** The DER tag of the value; one of the tag_ constants. */
    public byte         tag;

    /**
     * Create a DER input stream from a data buffer.  The buffer is not
     * copied, it is shared.  Accordingly, the buffer should be treated
     * as read-only.
     *
     * @param data the buffer from which to create the string (CONSUMED)
     */
    public TDerInputStream(byte[] data) throws IOException {
        init(data, 0, data.length, true);
    }

    /**
     * Create a DER input stream from part of a data buffer with
     * additional arg to control whether DER checks are enforced.
     * The buffer is not copied, it is shared.  Accordingly, the
     * buffer should be treated as read-only.
     *
     * @param data the buffer from which to create the string (CONSUMED)
     * @param offset the first index of <em>data</em> which will
     *          be read as DER input in the new stream
     * @param len how long a chunk of the buffer to use,
     *          starting at "offset"
     * @param allowBER whether to allow constructed indefinite-length
     *          encoding as well as tolerate leading 0s
     */
    public TDerInputStream(byte[] data, int offset, int len,
            boolean allowBER) throws IOException {
        init(data, offset, len, allowBER);
    }

    /**
     * Create a DER input stream from part of a data buffer.
     * The buffer is not copied, it is shared.  Accordingly, the
     * buffer should be treated as read-only.
     *
     * @param data the buffer from which to create the string (CONSUMED)
     * @param offset the first index of <em>data</em> which will
     *          be read as DER input in the new stream
     * @param len how long a chunk of the buffer to use,
     *          starting at "offset"
     */
    public TDerInputStream(byte[] data, int offset, int len) throws IOException {
        init(data, offset, len, true);
    }

    /*
     * private helper routine
     */
    private void init(byte[] data, int offset, int len, boolean allowBER) throws IOException {
        if ((offset+2 > data.length) || (offset+len > data.length)) {
            throw new IOException("Encoding bytes too short");
        }
        // check for indefinite length encoding
        if (TDerIndefLenConverter.isIndefinite(data[offset+1])) {
            if (!allowBER) {
                throw new IOException("Indefinite length BER encoding found");
            } else {
                byte[] inData = new byte[len];
                System.arraycopy(data, offset, inData, 0, len);

                TDerIndefLenConverter derIn = new TDerIndefLenConverter();
                buffer = new TDerInputBuffer(derIn.convert(inData), allowBER);
            }
        } else {
            buffer = new TDerInputBuffer(data, offset, len, allowBER);
        }
        buffer.mark(Integer.MAX_VALUE);
    }

    TDerInputStream(TDerInputBuffer buf) {
        buffer = buf;
        buffer.mark(Integer.MAX_VALUE);
    }

    /**
     * Creates a new DER input stream from part of this input stream.
     *
     * @param len how long a chunk of the current input stream to use,
     *          starting at the current position.
     * @param do_skip true if the existing data in the input stream should
     *          be skipped.  If this value is false, the next data read
     *          on this stream and the newly created stream will be the
     *          same.
     */
    public TDerInputStream subStream(int len, boolean do_skip)
            throws IOException {
        TDerInputBuffer newbuf = buffer.dup();

        newbuf.truncate(len);
        if (do_skip) {
            buffer.skip(len);
        }
        return new TDerInputStream(newbuf);
    }

    /**
     * Return what has been written to this DerInputStream
     * as a byte array. Useful for debugging.
     */
    public byte[] toByteArray() {
        return buffer.toByteArray();
    }

    /*
     * PRIMITIVES -- these are "universal" ASN.1 simple types.
     *
     *  INTEGER, ENUMERATED, BIT STRING, OCTET STRING, NULL
     *  OBJECT IDENTIFIER, SEQUENCE (OF), SET (OF)
     *  UTF8String, PrintableString, T61String, IA5String, UTCTime,
     *  GeneralizedTime, BMPString.
     * Note: UniversalString not supported till encoder is available.
     */

    /**
     * Get an integer from the input stream as an integer.
     *
     * @return the integer held in this DER input stream.
     */
    public int getInteger() throws IOException {
        if (buffer.read() != TDerValue.tag_Integer) {
            throw new IOException("DER input, Integer tag error");
        }
        return buffer.getInteger(getDefiniteLength(buffer));
    }

    /**
     * Get a integer from the input stream as a BigInteger object.
     *
     * @return the integer held in this DER input stream.
     */
    public BigInteger getBigInteger() throws IOException {
        if (buffer.read() != TDerValue.tag_Integer) {
            throw new IOException("DER input, Integer tag error");
        }
        return buffer.getBigInteger(getDefiniteLength(buffer), false);
    }

    /**
     * Returns an ASN.1 INTEGER value as a positive BigInteger.
     * This is just to deal with implementations that incorrectly encode
     * some values as negative.
     *
     * @return the integer held in this DER value as a BigInteger.
     */
    public BigInteger getPositiveBigInteger() throws IOException {
        if (buffer.read() != TDerValue.tag_Integer) {
            throw new IOException("DER input, Integer tag error");
        }
        return buffer.getBigInteger(getDefiniteLength(buffer), true);
    }

    /**
     * Get an enumerated from the input stream.
     *
     * @return the integer held in this DER input stream.
     */
    public int getEnumerated() throws IOException {
        if (buffer.read() != TDerValue.tag_Enumerated) {
            throw new IOException("DER input, Enumerated tag error");
        }
        return buffer.getInteger(getDefiniteLength(buffer));
    }

    /**
     * Get a bit string from the input stream. Padded bits (if any)
     * will be stripped off before the bit string is returned.
     */
    public byte[] getBitString() throws IOException {
        if (buffer.read() != TDerValue.tag_BitString) {
            throw new IOException("DER input not an bit string");
        }

        return buffer.getBitString(getDefiniteLength(buffer));
    }

    /**
     * Get a bit string from the input stream.  The bit string need
     * not be byte-aligned.
     */
    public TBitArray getUnalignedBitString() throws IOException {
        if (buffer.read() != TDerValue.tag_BitString) {
            throw new IOException("DER input not a bit string");
        }

        int length = getDefiniteLength(buffer);

        if (length == 0) {
            return new TBitArray(0);
        }

        /*
         * First byte = number of excess bits in the last octet of the
         * representation.
         */
        length--;
        int excessBits = buffer.read();
        if (excessBits < 0) {
            throw new IOException("Unused bits of bit string invalid");
        }
        int validBits = length*8 - excessBits;
        if (validBits < 0) {
            throw new IOException("Valid bits of bit string invalid");
        }

        byte[] repn = new byte[length];

        if ((length != 0) && (buffer.read(repn) != length)) {
            throw new IOException("Short read of DER bit string");
        }

        return new TBitArray(validBits, repn);
    }

    /**
     * Returns an ASN.1 OCTET STRING from the input stream.
     */
    public byte[] getOctetString() throws IOException {
        if (buffer.read() != TDerValue.tag_OctetString) {
            throw new IOException("DER input not an octet string");
        }

        int length = getDefiniteLength(buffer);
        byte[] retval = new byte[length];
        if ((length != 0) && (buffer.read(retval) != length)) {
            throw new IOException("Short read of DER octet string");
        }

        return retval;
    }

    /**
     * Returns the asked number of bytes from the input stream.
     */
    public void getBytes(byte[] val) throws IOException {
        if ((val.length != 0) && (buffer.read(val) != val.length)) {
            throw new IOException("Short read of DER octet string");
        }
    }

    /**
     * Reads an encoded null value from the input stream.
     */
    public void getNull() throws IOException {
        if (buffer.read() != TDerValue.tag_Null || buffer.read() != 0) {
            throw new IOException("getNull, bad data");
        }
    }

    /**
     * Reads an X.200 style Object Identifier from the stream.
     */
    public TObjectIdentifier getOID() throws IOException {
        return new TObjectIdentifier(this);
    }

    /**
     * Return a sequence of encoded entities.  ASN.1 sequences are
     * ordered, and they are often used, like a "struct" in C or C++,
     * to group data values.  They may have optional or context
     * specific values.
     *
     * @param startLen guess about how long the sequence will be
     *          (used to initialize an auto-growing data structure)
     * @return array of the values in the sequence
     */
    public TDerValue[] getSequence(int startLen) throws IOException {
        tag = (byte)buffer.read();
        if (tag != TDerValue.tag_Sequence) {
            throw new IOException("Sequence tag error");
        }
        return readVector(startLen);
    }

    /**
     * Return a set of encoded entities.  ASN.1 sets are unordered,
     * though DER may specify an order for some kinds of sets (such
     * as the attributes in an X.500 relative distinguished name)
     * to facilitate binary comparisons of encoded values.
     *
     * @param startLen guess about how large the set will be
     *          (used to initialize an auto-growing data structure)
     * @return array of the values in the sequence
     */
    public TDerValue[] getSet(int startLen) throws IOException {
        tag = (byte)buffer.read();
        if (tag != TDerValue.tag_Set) {
            throw new IOException("Set tag error");
        }
        return readVector(startLen);
    }

    /**
     * Return a set of encoded entities.  ASN.1 sets are unordered,
     * though DER may specify an order for some kinds of sets (such
     * as the attributes in an X.500 relative distinguished name)
     * to facilitate binary comparisons of encoded values.
     *
     * @param startLen guess about how large the set will be
     *          (used to initialize an auto-growing data structure)
     * @param implicit if true tag is assumed implicit.
     * @return array of the values in the sequence
     */
    public TDerValue[] getSet(int startLen, boolean implicit)
            throws IOException {
        tag = (byte)buffer.read();
        if (!implicit) {
            if (tag != TDerValue.tag_Set) {
                throw new IOException("Set tag error");
            }
        }
        return (readVector(startLen));
    }

    /*
     * Read a "vector" of values ... set or sequence have the
     * same encoding, except for the initial tag, so both use
     * this same helper routine.
     */
    protected TDerValue[] readVector(int startLen) throws IOException {
        TDerInputStream newstr;

        byte lenByte = (byte)buffer.read();
        int len = getLength(lenByte, buffer);

        if (len == -1) {
            // indefinite length encoding found
            int readLen = buffer.available();
            int offset = 2;     // for tag and length bytes
            byte[] indefData = new byte[readLen + offset];
            indefData[0] = tag;
            indefData[1] = lenByte;
            DataInputStream dis = new DataInputStream(buffer);
            dis.readFully(indefData, offset, readLen);
            dis.close();
            TDerIndefLenConverter derIn = new TDerIndefLenConverter();
            buffer = new TDerInputBuffer(derIn.convert(indefData), buffer.allowBER);

            if (tag != buffer.read()) {
                throw new IOException("Indefinite length encoding" +
                        " not supported");
            }
            len = TDerInputStream.getDefiniteLength(buffer);
        }

        if (len == 0)
            // return empty array instead of null, which should be
            // used only for missing optionals
        {
            return new TDerValue[0];
        }

        /*
         * Create a temporary stream from which to read the data,
         * unless it's not really needed.
         */
        if (buffer.available() == len) {
            newstr = this;
        } else {
            newstr = subStream(len, true);
        }

        /*
         * Pull values out of the stream.
         */
        Vector<TDerValue> vec = new Vector<>(startLen);
        TDerValue value;

        do {
            value = new TDerValue(newstr.buffer, buffer.allowBER);
            vec.addElement(value);
        } while (newstr.available() > 0);

        if (newstr.available() != 0) {
            throw new IOException("Extra data at end of vector");
        }

        /*
         * Now stick them into the array we're returning.
         */
        int             i, max = vec.size();
        TDerValue[]      retval = new TDerValue[max];

        for (i = 0; i < max; i++) {
            retval[i] = vec.elementAt(i);
        }

        return retval;
    }

    /**
     * Get a single DER-encoded value from the input stream.
     * It can often be useful to pull a value from the stream
     * and defer parsing it.  For example, you can pull a nested
     * sequence out with one call, and only examine its elements
     * later when you really need to.
     */
    public TDerValue getDerValue() throws IOException {
        return new TDerValue(buffer);
    }

    /**
     * Read a string that was encoded as a UTF8String DER value.
     */
    public String getUTF8String() throws IOException {
        return readString(TDerValue.tag_UTF8String, "UTF-8", "UTF8");
    }

    /**
     * Read a string that was encoded as a PrintableString DER value.
     */
    public String getPrintableString() throws IOException {
        return readString(TDerValue.tag_PrintableString, "Printable",
                "ASCII");
    }

    /**
     * Read a string that was encoded as a T61String DER value.
     */
    public String getT61String() throws IOException {
        /*
         * Works for common characters between T61 and ASCII.
         */
        return readString(TDerValue.tag_T61String, "T61", "ISO-8859-1");
    }

    /**
     * Read a string that was encoded as a IA5tring DER value.
     */
    public String getIA5String() throws IOException {
        return readString(TDerValue.tag_IA5String, "IA5", "ASCII");
    }

    /**
     * Read a string that was encoded as a BMPString DER value.
     */
    public String getBMPString() throws IOException {
        return readString(TDerValue.tag_BMPString, "BMP",
                "UnicodeBigUnmarked");
    }

    /**
     * Read a string that was encoded as a GeneralString DER value.
     */
    public String getGeneralString() throws IOException {
        return readString(TDerValue.tag_GeneralString, "General",
                "ASCII");
    }

    /**
     * Private helper routine to read an encoded string from the input
     * stream.
     * @param stringTag the tag for the type of string to read
     * @param stringName a name to display in error messages
     * @param enc the encoder to use to interpret the data. Should
     * correspond to the stringTag above.
     */
    private String readString(byte stringTag, String stringName,
            String enc) throws IOException {

        if (buffer.read() != stringTag) {
            throw new IOException("DER input not a " +
                    stringName + " string");
        }

        int length = getDefiniteLength(buffer);
        byte[] retval = new byte[length];
        if ((length != 0) && (buffer.read(retval) != length)) {
            throw new IOException("Short read of DER " +
                    stringName + " string");
        }

        return new String(retval, enc);
    }

    /**
     * Get a UTC encoded time value from the input stream.
     */
    public Date getUTCTime() throws IOException {
        if (buffer.read() != TDerValue.tag_UtcTime) {
            throw new IOException("DER input, UTCtime tag invalid ");
        }
        return buffer.getUTCTime(getDefiniteLength(buffer));
    }

    /**
     * Get a Generalized encoded time value from the input stream.
     */
    public Date getGeneralizedTime() throws IOException {
        if (buffer.read() != TDerValue.tag_GeneralizedTime) {
            throw new IOException("DER input, GeneralizedTime tag invalid ");
        }
        return buffer.getGeneralizedTime(getDefiniteLength(buffer));
    }

    /*
     * Get a byte from the input stream.
     */
    // package private
    int getByte() throws IOException {
        return (0x00ff & buffer.read());
    }

    public int peekByte() throws IOException {
        return buffer.peek();
    }

    // package private
    int getLength() throws IOException {
        return getLength(buffer);
    }

    /*
     * Get a length from the input stream, allowing for at most 32 bits of
     * encoding to be used.  (Not the same as getting a tagged integer!)
     *
     * @return the length or -1 if indefinite length found.
     * @exception IOException on parsing error or unsupported lengths.
     */
    static int getLength(InputStream in) throws IOException {
        return getLength(in.read(), in);
    }

    /*
     * Get a length from the input stream, allowing for at most 32 bits of
     * encoding to be used.  (Not the same as getting a tagged integer!)
     *
     * @return the length or -1 if indefinite length found.
     * @exception IOException on parsing error or unsupported lengths.
     */
    static int getLength(int lenByte, InputStream in) throws IOException {
        int value, tmp;
        if (lenByte == -1) {
            throw new IOException("Short read of DER length");
        }

        String mdName = "DerInputStream.getLength(): ";
        tmp = lenByte;
        if ((tmp & 0x080) == 0x00) { // short form, 1 byte datum
            value = tmp;
        } else {                     // long form or indefinite
            tmp &= 0x07f;

            /*
             * NOTE:  tmp == 0 indicates indefinite length encoded data.
             * tmp > 4 indicates more than 4Gb of data.
             */
            if (tmp == 0) {
                return -1;
            }
            if (tmp < 0 || tmp > 4) {
                throw new IOException(mdName + "lengthTag=" + tmp + ", "
                        + ((tmp < 0) ? "incorrect DER encoding." : "too big."));
            }

            value = 0x0ff & in.read();
            tmp--;
            if (value == 0) {
                // DER requires length value be encoded in minimum number of bytes
                throw new IOException(mdName + "Redundant length bytes found");
            }
            while (tmp-- > 0) {
                value <<= 8;
                value += 0x0ff & in.read();
            }
            if (value < 0) {
                throw new IOException(mdName + "Invalid length bytes");
            } else if (value <= 127) {
                throw new IOException(mdName + "Should use short form for length");
            }
        }
        return value;
    }

    int getDefiniteLength() throws IOException {
        return getDefiniteLength(buffer);
    }

    /*
     * Get a length from the input stream.
     *
     * @return the length
     * @exception IOException on parsing error or if indefinite length found.
     */
    static int getDefiniteLength(InputStream in) throws IOException {
        int len = getLength(in);
        if (len < 0) {
            throw new IOException("Indefinite length encoding not supported");
        }
        return len;
    }

    /**
     * Mark the current position in the buffer, so that
     * a later call to <code>reset</code> will return here.
     */
    public void mark(int value) { buffer.mark(value); }


    /**
     * Return to the position of the last <code>mark</code>
     * call.  A mark is implicitly set at the beginning of
     * the stream when it is created.
     */
    public void reset() { buffer.reset(); }


    /**
     * Returns the number of bytes available for reading.
     * This is most useful for testing whether the stream is
     * empty.
     */
    public int available() { return buffer.available(); }
}

