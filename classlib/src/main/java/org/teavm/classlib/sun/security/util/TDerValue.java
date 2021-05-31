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

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Date;

public class TDerValue {
    /** The tag class types */
    public static final byte TAG_UNIVERSAL = (byte)0x000;
    public static final byte TAG_APPLICATION = (byte)0x040;
    public static final byte TAG_CONTEXT = (byte)0x080;
    public static final byte TAG_PRIVATE = (byte)0x0c0;

    /** The DER tag of the value; one of the tag_ constants. */
    public byte                 tag;

    protected TDerInputBuffer buffer;

    /**
     * The DER-encoded data of the value, never null
     */
    public final TDerInputStream data;

    private int                 length;

    /*
     * The type starts at the first byte of the encoding, and
     * is one of these tag_* values.  That may be all the type
     * data that is needed.
     */

    /*
     * These tags are the "universal" tags ... they mean the same
     * in all contexts.  (Mask with 0x1f -- five bits.)
     */

    /** Tag value indicating an ASN.1 "BOOLEAN" value. */
    public static final byte    tag_Boolean = 0x01;

    /** Tag value indicating an ASN.1 "INTEGER" value. */
    public static final byte    tag_Integer = 0x02;

    /** Tag value indicating an ASN.1 "BIT STRING" value. */
    public static final byte    tag_BitString = 0x03;

    /** Tag value indicating an ASN.1 "OCTET STRING" value. */
    public static final byte    tag_OctetString = 0x04;

    /** Tag value indicating an ASN.1 "NULL" value. */
    public static final byte    tag_Null = 0x05;

    /** Tag value indicating an ASN.1 "OBJECT IDENTIFIER" value. */
    public static final byte    tag_ObjectId = 0x06;

    /** Tag value including an ASN.1 "ENUMERATED" value */
    public static final byte    tag_Enumerated = 0x0A;

    /** Tag value indicating an ASN.1 "UTF8String" value. */
    public static final byte    tag_UTF8String = 0x0C;

    /** Tag value including a "printable" string */
    public static final byte    tag_PrintableString = 0x13;

    /** Tag value including a "teletype" string */
    public static final byte    tag_T61String = 0x14;

    /** Tag value including an ASCII string */
    public static final byte    tag_IA5String = 0x16;

    /** Tag value indicating an ASN.1 "UTCTime" value. */
    public static final byte    tag_UtcTime = 0x17;

    /** Tag value indicating an ASN.1 "GeneralizedTime" value. */
    public static final byte    tag_GeneralizedTime = 0x18;

    /** Tag value indicating an ASN.1 "GenerallString" value. */
    public static final byte    tag_GeneralString = 0x1B;

    /** Tag value indicating an ASN.1 "UniversalString" value. */
    public static final byte    tag_UniversalString = 0x1C;

    /** Tag value indicating an ASN.1 "BMPString" value. */
    public static final byte    tag_BMPString = 0x1E;

    // CONSTRUCTED seq/set

    /**
     * Tag value indicating an ASN.1
     * "SEQUENCE" (zero to N elements, order is significant).
     */
    public static final byte    tag_Sequence = 0x30;

    /**
     * Tag value indicating an ASN.1
     * "SEQUENCE OF" (one to N elements, order is significant).
     */
    public static final byte    tag_SequenceOf = 0x30;

    /**
     * Tag value indicating an ASN.1
     * "SET" (zero to N members, order does not matter).
     */
    public static final byte    tag_Set = 0x31;

    /**
     * Tag value indicating an ASN.1
     * "SET OF" (one to N members, order does not matter).
     */
    public static final byte    tag_SetOf = 0x31;

    /*
     * These values are the high order bits for the other kinds of tags.
     */

    /**
     * Returns true if the tag class is UNIVERSAL.
     */
    public boolean isUniversal()      { return ((tag & 0x0c0) == 0x000); }

    /**
     * Returns true if the tag class is APPLICATION.
     */
    public boolean isApplication()    { return ((tag & 0x0c0) == 0x040); }

    /**
     * Returns true iff the CONTEXT SPECIFIC bit is set in the type tag.
     * This is associated with the ASN.1 "DEFINED BY" syntax.
     */
    public boolean isContextSpecific() { return ((tag & 0x0c0) == 0x080); }

    /**
     * Returns true iff the CONTEXT SPECIFIC TAG matches the passed tag.
     */
    public boolean isContextSpecific(byte cntxtTag) {
        if (!isContextSpecific()) {
            return false;
        }
        return ((tag & 0x01f) == cntxtTag);
    }

    boolean isPrivate()        { return ((tag & 0x0c0) == 0x0c0); }

    /** Returns true iff the CONSTRUCTED bit is set in the type tag. */
    public boolean isConstructed()    { return ((tag & 0x020) == 0x020); }

    /**
     * Returns true iff the CONSTRUCTED TAG matches the passed tag.
     */
    public boolean isConstructed(byte constructedTag) {
        if (!isConstructed()) {
            return false;
        }
        return ((tag & 0x01f) == constructedTag);
    }

    /**
     * Creates a PrintableString or UTF8string DER value from a string
     */
    public TDerValue(String value) throws IOException {
        boolean isPrintableString = true;
        for (int i = 0; i < value.length(); i++) {
            if (!isPrintableStringChar(value.charAt(i))) {
                isPrintableString = false;
                break;
            }
        }

        data = init(isPrintableString ? tag_PrintableString : tag_UTF8String, value);
    }

    /**
     * Creates a string type DER value from a String object
     * @param stringTag the tag for the DER value to create
     * @param value the String object to use for the DER value
     */
    public TDerValue(byte stringTag, String value) throws IOException {
        data = init(stringTag, value);
    }

    // Creates a DerValue from a tag and some DER-encoded data w/ additional
    // arg to control whether DER checks are enforced.
    TDerValue(byte tag, byte[] data, boolean allowBER) {
        this.tag = tag;
        buffer = new TDerInputBuffer(data.clone(), allowBER);
        length = data.length;
        this.data = new TDerInputStream(buffer);
        this.data.mark(Integer.MAX_VALUE);
    }

    /**
     * Creates a DerValue from a tag and some DER-encoded data.
     *
     * @param tag the DER type tag
     * @param data the DER-encoded data
     */
    public TDerValue(byte tag, byte[] data) {
        this(tag, data, true);
    }

    /*
     * package private
     */
    TDerValue(TDerInputBuffer in) throws IOException {

        // XXX must also parse BER-encoded constructed
        // values such as sequences, sets...
        tag = (byte)in.read();
        byte lenByte = (byte)in.read();
        length = TDerInputStream.getLength(lenByte, in);
        if (length == -1) {  // indefinite length encoding found
            TDerInputBuffer inbuf = in.dup();
            int readLen = inbuf.available();
            int offset = 2;     // for tag and length bytes
            byte[] indefData = new byte[readLen + offset];
            indefData[0] = tag;
            indefData[1] = lenByte;
            DataInputStream dis = new DataInputStream(inbuf);
            dis.readFully(indefData, offset, readLen);
            dis.close();
            TDerIndefLenConverter derIn = new TDerIndefLenConverter();
            inbuf = new TDerInputBuffer(derIn.convert(indefData), in.allowBER);
            if (tag != inbuf.read()) {
                throw new IOException
                        ("Indefinite length encoding not supported");
            }
            length = TDerInputStream.getDefiniteLength(inbuf);
            buffer = inbuf.dup();
            buffer.truncate(length);
            data = new TDerInputStream(buffer);
            // indefinite form is encoded by sending a length field with a
            // length of 0. - i.e. [1000|0000].
            // the object is ended by sending two zero bytes.
            in.skip(length + offset);
        } else {

            buffer = in.dup();
            buffer.truncate(length);
            data = new TDerInputStream(buffer);

            in.skip(length);
        }
    }

    // Get an ASN.1/DER encoded datum from a buffer w/ additional
    // arg to control whether DER checks are enforced.
    TDerValue(byte[] buf, boolean allowBER) throws IOException {
        data = init(true, new ByteArrayInputStream(buf), allowBER);
    }

    /**
     * Get an ASN.1/DER encoded datum from a buffer.  The
     * entire buffer must hold exactly one datum, including
     * its tag and length.
     *
     * @param buf buffer holding a single DER-encoded datum.
     */
    public TDerValue(byte[] buf) throws IOException {
        this(buf, true);
    }

    // Get an ASN.1/DER encoded datum from part of a buffer w/ additional
    // arg to control whether DER checks are enforced.
    TDerValue(byte[] buf, int offset, int len, boolean allowBER)
            throws IOException {
        data = init(true, new ByteArrayInputStream(buf, offset, len), allowBER);
    }

    /**
     * Get an ASN.1/DER encoded datum from part of a buffer.
     * That part of the buffer must hold exactly one datum, including
     * its tag and length.
     *
     * @param buf the buffer
     * @param offset start point of the single DER-encoded dataum
     * @param len how many bytes are in the encoded datum
     */
    public TDerValue(byte[] buf, int offset, int len) throws IOException {
        this(buf, offset, len, true);
    }

    // Get an ASN1/DER encoded datum from an input stream w/ additional
    // arg to control whether DER checks are enforced.
    TDerValue(InputStream in, boolean allowBER) throws IOException {
        data = init(false, in, allowBER);
    }

    /**
     * Get an ASN1/DER encoded datum from an input stream.  The
     * stream may have additional data following the encoded datum.
     * In case of indefinite length encoded datum, the input stream
     * must hold only one datum.
     *
     * @param in the input stream holding a single DER datum,
     *  which may be followed by additional data
     */
    public TDerValue(InputStream in) throws IOException {
        this(in, true);
    }

    private TDerInputStream init(byte stringTag, String value)
            throws IOException {
        String enc = null;

        tag = stringTag;

        switch (stringTag) {
            case tag_PrintableString:
            case tag_IA5String:
            case tag_GeneralString:
                enc = "ASCII";
                break;
            case tag_T61String:
                enc = "ISO-8859-1";
                break;
            case tag_BMPString:
                enc = "UnicodeBigUnmarked";
                break;
            case tag_UTF8String:
                enc = "UTF8";
                break;
            // TBD: Need encoder for UniversalString before it can
            // be handled.
            default:
                throw new IllegalArgumentException("Unsupported DER string type");
        }

        byte[] buf = value.getBytes(enc);
        length = buf.length;
        buffer = new TDerInputBuffer(buf, true);
        TDerInputStream result = new TDerInputStream(buffer);
        result.mark(Integer.MAX_VALUE);
        return result;
    }

    /*
     * helper routine
     */
    private TDerInputStream init(boolean fullyBuffered, InputStream in,
            boolean allowBER) throws IOException {

        tag = (byte)in.read();
        byte lenByte = (byte)in.read();
        length = TDerInputStream.getLength(lenByte, in);
        if (length == -1) { // indefinite length encoding found
            int readLen = in.available();
            int offset = 2;     // for tag and length bytes
            byte[] indefData = new byte[readLen + offset];
            indefData[0] = tag;
            indefData[1] = lenByte;
            DataInputStream dis = new DataInputStream(in);
            dis.readFully(indefData, offset, readLen);
            dis.close();
            TDerIndefLenConverter derIn = new TDerIndefLenConverter();
            in = new ByteArrayInputStream(derIn.convert(indefData));
            if (tag != in.read()) {
                throw new IOException
                        ("Indefinite length encoding not supported");
            }
            length = TDerInputStream.getDefiniteLength(in);
        }

        if (fullyBuffered && in.available() != length) {
            throw new IOException("extra data given to DerValue constructor");
        }

        byte[] bytes = TIOUtils.readExactlyNBytes(in, length);

        buffer = new TDerInputBuffer(bytes, allowBER);
        return new TDerInputStream(buffer);
    }

    /**
     * Encode an ASN1/DER encoded datum onto a DER output stream.
     */
    public void encode(TDerOutputStream out)
            throws IOException {
        out.write(tag);
        out.putLength(length);
        // XXX yeech, excess copies ... DerInputBuffer.write(OutStream)
        if (length > 0) {
            byte[] value = new byte[length];
            // always synchronized on data
            synchronized (data) {
                buffer.reset();
                if (buffer.read(value) != length) {
                    throw new IOException("short DER value read (encode)");
                }
                out.write(value);
            }
        }
    }

    public final TDerInputStream getData() {
        return data;
    }

    public final byte getTag() {
        return tag;
    }

    /**
     * Returns an ASN.1 BOOLEAN
     *
     * @return the boolean held in this DER value
     */
    public boolean getBoolean() throws IOException {
        if (tag != tag_Boolean) {
            throw new IOException("DerValue.getBoolean, not a BOOLEAN " + tag);
        }
        if (length != 1) {
            throw new IOException("DerValue.getBoolean, invalid length "
                    + length);
        }
        if (buffer.read() != 0) {
            return true;
        }
        return false;
    }

    /**
     * Returns an ASN.1 OBJECT IDENTIFIER.
     *
     * @return the OID held in this DER value
     */
    public TObjectIdentifier getOID() throws IOException {
        if (tag != tag_ObjectId) {
            throw new IOException("DerValue.getOID, not an OID " + tag);
        }
        return new TObjectIdentifier(buffer);
    }

    private byte[] append(byte[] a, byte[] b) {
        if (a == null) {
            return b;
        }

        byte[] ret = new byte[a.length + b.length];
        System.arraycopy(a, 0, ret, 0, a.length);
        System.arraycopy(b, 0, ret, a.length, b.length);

        return ret;
    }

    /**
     * Returns an ASN.1 OCTET STRING
     *
     * @return the octet string held in this DER value
     */
    public byte[] getOctetString() throws IOException {

        if (tag != tag_OctetString && !isConstructed(tag_OctetString)) {
            throw new IOException(
                    "DerValue.getOctetString, not an Octet String: " + tag);
        }
        // Note: do not attempt to call buffer.read(bytes) at all. There's a
        // known bug that it returns -1 instead of 0.
        if (length == 0) {
            return new byte[0];
        }

        // Only allocate the array if there are enough bytes available.
        // This only works for ByteArrayInputStream.
        // The assignment below ensures that buffer has the required type.
        ByteArrayInputStream arrayInput = buffer;
        if (arrayInput.available() < length) {
            throw new IOException("short read on DerValue buffer");
        }
        byte[] bytes = new byte[length];
        arrayInput.read(bytes);

        if (isConstructed()) {
            TDerInputStream in = new TDerInputStream(bytes, 0, bytes.length,
                    buffer.allowBER);
            bytes = null;
            while (in.available() != 0) {
                bytes = append(bytes, in.getOctetString());
            }
        }
        return bytes;
    }

    /**
     * Returns an ASN.1 INTEGER value as an integer.
     *
     * @return the integer held in this DER value.
     */
    public int getInteger() throws IOException {
        if (tag != tag_Integer) {
            throw new IOException("DerValue.getInteger, not an int " + tag);
        }
        return buffer.getInteger(data.available());
    }

    /**
     * Returns an ASN.1 INTEGER value as a BigInteger.
     *
     * @return the integer held in this DER value as a BigInteger.
     */
    public BigInteger getBigInteger() throws IOException {
        if (tag != tag_Integer) {
            throw new IOException("DerValue.getBigInteger, not an int " + tag);
        }
        return buffer.getBigInteger(data.available(), false);
    }

    /**
     * Returns an ASN.1 INTEGER value as a positive BigInteger.
     * This is just to deal with implementations that incorrectly encode
     * some values as negative.
     *
     * @return the integer held in this DER value as a BigInteger.
     */
    public BigInteger getPositiveBigInteger() throws IOException {
        if (tag != tag_Integer) {
            throw new IOException("DerValue.getBigInteger, not an int " + tag);
        }
        return buffer.getBigInteger(data.available(), true);
    }

    /**
     * Returns an ASN.1 ENUMERATED value.
     *
     * @return the integer held in this DER value.
     */
    public int getEnumerated() throws IOException {
        if (tag != tag_Enumerated) {
            throw new IOException("DerValue.getEnumerated, incorrect tag: "
                    + tag);
        }
        return buffer.getInteger(data.available());
    }

    /**
     * Returns an ASN.1 BIT STRING value.  The bit string must be byte-aligned.
     *
     * @return the bit string held in this value
     */
    public byte[] getBitString() throws IOException {
        if (tag != tag_BitString) {
            throw new IOException(
                    "DerValue.getBitString, not a bit string " + tag);
        }

        return buffer.getBitString();
    }

    /**
     * Returns an ASN.1 BIT STRING value that need not be byte-aligned.
     *
     * @return a BitArray representing the bit string held in this value
     */
    public TBitArray getUnalignedBitString() throws IOException {
        if (tag != tag_BitString) {
            throw new IOException(
                    "DerValue.getBitString, not a bit string " + tag);
        }

        return buffer.getUnalignedBitString();
    }

    /**
     * Returns the name component as a Java string, regardless of its
     * encoding restrictions (ASCII, T61, Printable, IA5, BMP, UTF8).
     */
    // TBD: Need encoder for UniversalString before it can be handled.
    public String getAsString() throws IOException {
        if (tag == tag_UTF8String) {
            return getUTF8String();
        } else if (tag == tag_PrintableString) {
            return getPrintableString();
        } else if (tag == tag_T61String) {
            return getT61String();
        } else if (tag == tag_IA5String) {
            return getIA5String();
        }
        /*
          else if (tag == tag_UniversalString)
          return getUniversalString();
        */
        else if (tag == tag_BMPString) {
            return getBMPString();
        } else if (tag == tag_GeneralString) {
            return getGeneralString();
        } else {
            return null;
        }
    }

    /**
     * Returns an ASN.1 BIT STRING value, with the tag assumed implicit
     * based on the parameter.  The bit string must be byte-aligned.
     *
     * @param tagImplicit if true, the tag is assumed implicit.
     * @return the bit string held in this value
     */
    public byte[] getBitString(boolean tagImplicit) throws IOException {
        if (!tagImplicit) {
            if (tag != tag_BitString) {
                throw new IOException("DerValue.getBitString, not a bit string "
                        + tag);
            }
        }
        return buffer.getBitString();
    }

    /**
     * Returns an ASN.1 BIT STRING value, with the tag assumed implicit
     * based on the parameter.  The bit string need not be byte-aligned.
     *
     * @param tagImplicit if true, the tag is assumed implicit.
     * @return the bit string held in this value
     */
    public TBitArray getUnalignedBitString(boolean tagImplicit)
            throws IOException {
        if (!tagImplicit) {
            if (tag != tag_BitString) {
                throw new IOException("DerValue.getBitString, not a bit string "
                        + tag);
            }
        }
        return buffer.getUnalignedBitString();
    }

    /**
     * Helper routine to return all the bytes contained in the
     * TDerInputStream associated with this object.
     */
    public byte[] getDataBytes() throws IOException {
        byte[] retVal = new byte[length];
        synchronized (data) {
            data.reset();
            data.getBytes(retVal);
        }
        return retVal;
    }

    /**
     * Returns an ASN.1 STRING value
     *
     * @return the printable string held in this value
     */
    public String getPrintableString()
            throws IOException {
        if (tag != tag_PrintableString) {
            throw new IOException(
                    "DerValue.getPrintableString, not a string " + tag);
        }

        return new String(getDataBytes(), "ASCII");
    }

    /**
     * Returns an ASN.1 T61 (Teletype) STRING value
     *
     * @return the teletype string held in this value
     */
    public String getT61String() throws IOException {
        if (tag != tag_T61String) {
            throw new IOException(
                    "DerValue.getT61String, not T61 " + tag);
        }

        return new String(getDataBytes(), "ISO-8859-1");
    }

    /**
     * Returns an ASN.1 IA5 (ASCII) STRING value
     *
     * @return the ASCII string held in this value
     */
    public String getIA5String() throws IOException {
        if (tag != tag_IA5String) {
            throw new IOException(
                    "DerValue.getIA5String, not IA5 " + tag);
        }

        return new String(getDataBytes(), "ASCII");
    }

    /**
     * Returns the ASN.1 BMP (Unicode) STRING value as a Java string.
     *
     * @return a string corresponding to the encoded BMPString held in
     * this value
     */
    public String getBMPString() throws IOException {
        if (tag != tag_BMPString) {
            throw new IOException(
                    "DerValue.getBMPString, not BMP " + tag);
        }

        // BMPString is the same as Unicode in big endian, unmarked
        // format.
        return new String(getDataBytes(), "UnicodeBigUnmarked");
    }

    /**
     * Returns the ASN.1 UTF-8 STRING value as a Java String.
     *
     * @return a string corresponding to the encoded UTF8String held in
     * this value
     */
    public String getUTF8String() throws IOException {
        if (tag != tag_UTF8String) {
            throw new IOException(
                    "DerValue.getUTF8String, not UTF-8 " + tag);
        }

        return new String(getDataBytes(), "UTF8");
    }

    /**
     * Returns the ASN.1 GENERAL STRING value as a Java String.
     *
     * @return a string corresponding to the encoded GeneralString held in
     * this value
     */
    public String getGeneralString() throws IOException {
        if (tag != tag_GeneralString) {
            throw new IOException(
                    "DerValue.getGeneralString, not GeneralString " + tag);
        }

        return new String(getDataBytes(), "ASCII");
    }

    /**
     * Returns a Date if the DerValue is UtcTime.
     *
     * @return the Date held in this DER value
     */
    public Date getUTCTime() throws IOException {
        if (tag != tag_UtcTime) {
            throw new IOException("DerValue.getUTCTime, not a UtcTime: " + tag);
        }
        return buffer.getUTCTime(data.available());
    }

    /**
     * Returns a Date if the DerValue is GeneralizedTime.
     *
     * @return the Date held in this DER value
     */
    public Date getGeneralizedTime() throws IOException {
        if (tag != tag_GeneralizedTime) {
            throw new IOException(
                    "DerValue.getGeneralizedTime, not a GeneralizedTime: " + tag);
        }
        return buffer.getGeneralizedTime(data.available());
    }

    /**
     * Bitwise equality comparison.  DER encoded values have a single
     * encoding, so that bitwise equality of the encoded values is an
     * efficient way to establish equivalence of the unencoded values.
     *
     * @param o the object being compared with this one
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof TDerValue)) {
            return false;
        }
        TDerValue other = (TDerValue) o;
        if (tag != other.tag) {
            return false;
        }
        if (data == other.data) {
            return true;
        }

        // make sure the order of lock is always consistent to avoid a deadlock
        return (System.identityHashCode(this.data)
                > System.identityHashCode(other.data)) ?
                doEquals(this, other):
                doEquals(other, this);
    }

    /**
     * Helper for public method equals()
     */
    private static boolean doEquals(TDerValue d1, TDerValue d2) {
        synchronized (d1.data) {
            synchronized (d2.data) {
                d1.data.reset();
                d2.data.reset();
                return d1.buffer.equals(d2.buffer);
            }
        }
    }

    /**
     * Returns a printable representation of the value.
     *
     * @return printable representation of the value
     */
    @Override
    public String toString() {
        try {

            String str = getAsString();
            if (str != null) {
                return "\"" + str + "\"";
            }
            if (tag == tag_Null) {
                return "[DerValue, null]";
            }
            if (tag == tag_ObjectId) {
                return "OID." + getOID();
            }

                // integers
            else {
                return "[DerValue, tag = " + tag
                        + ", length = " + length + "]";
            }
        } catch (IOException e) {
            throw new IllegalArgumentException("misformatted DER value");
        }
    }

    /**
     * Returns a DER-encoded value, such that if it's passed to the
     * DerValue constructor, a value equivalent to "this" is returned.
     *
     * @return DER-encoded value, including tag and length.
     */
    public byte[] toByteArray() throws IOException {
        TDerOutputStream out = new TDerOutputStream();

        encode(out);
        data.reset();
        return out.toByteArray();
    }

    /**
     * For "set" and "sequence" types, this function may be used
     * to return a DER stream of the members of the set or sequence.
     * This operation is not supported for primitive types such as
     * integers or bit strings.
     */
    public TDerInputStream toTDerInputStream() throws IOException {
        if (tag == tag_Sequence || tag == tag_Set) {
            return new TDerInputStream(buffer);
        }
        throw new IOException("toTDerInputStream rejects tag type " + tag);
    }

    /**
     * Get the length of the encoded value.
     */
    public int length() {
        return length;
    }

    /**
     * Determine if a character is one of the permissible characters for
     * PrintableString:
     * A-Z, a-z, 0-9, space, apostrophe (39), left and right parentheses,
     * plus sign, comma, hyphen, period, slash, colon, equals sign,
     * and question mark.
     *
     * Characters that are *not* allowed in PrintableString include
     * exclamation point, quotation mark, number sign, dollar sign,
     * percent sign, ampersand, asterisk, semicolon, less than sign,
     * greater than sign, at sign, left and right square brackets,
     * backslash, circumflex (94), underscore, back quote (96),
     * left and right curly brackets, vertical line, tilde,
     * and the control codes (0-31 and 127).
     *
     * This list is based on X.680 (the ASN.1 spec).
     */
    public static boolean isPrintableStringChar(char ch) {
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                (ch >= '0' && ch <= '9')) {
            return true;
        } else {
            switch (ch) {
                case ' ':       /* space */
                case '\'':      /* apostrophe */
                case '(':       /* left paren */
                case ')':       /* right paren */
                case '+':       /* plus */
                case ',':       /* comma */
                case '-':       /* hyphen */
                case '.':       /* period */
                case '/':       /* slash */
                case ':':       /* colon */
                case '=':       /* equals */
                case '?':       /* question mark */
                    return true;
                default:
                    return false;
            }
        }
    }

    /**
     * Create the tag of the attribute.
     *
     * @param tagClass the tag class type, one of UNIVERSAL, CONTEXT,
     *               APPLICATION or PRIVATE
     * @param form if true, the value is constructed, otherwise it
     * is primitive.
     * @param val the tag value
     */
    public static byte createTag(byte tagClass, boolean form, byte val) {
        byte tag = (byte)(tagClass | val);
        if (form) {
            tag |= (byte)0x20;
        }
        return (tag);
    }

    /**
     * Set the tag of the attribute. Commonly used to reset the
     * tag value used for IMPLICIT encodings.
     *
     * @param tag the tag value
     */
    public void resetTag(byte tag) {
        this.tag = tag;
    }

    /**
     * Returns a hashcode for this DerValue.
     *
     * @return a hashcode for this DerValue.
     */
    @Override
    public int hashCode() {
        return toString().hashCode();
    }
}

