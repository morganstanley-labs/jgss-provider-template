/*
 * Copyright 2023 Morgan Stanley
 *
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 * 
 *  - Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 *    disclaimer.
 *  
 *  - Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 *    following disclaimer in the documentation and/or other materials provided with the distribution.
 *  
 *  - Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written permission.
 *  
 *  
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package org.customjgss.impl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import org.ietf.jgss.GSSException;
import sun.security.jgss.GSSHeader;
import sun.security.util.ObjectIdentifier;

/**
 * Static utility methods related to reading bytes and GSS tokens form input streams.
 * <p/>
 * NOTE that this demonstration doesn't use this class because it just delegates to the built-in classes, however a real
 * one would need it as described in CustomGSSContextSpiImpl's initSecContext and acceptSecContext methods. The comments
 * in this class describe the requirements for that in more detail.
 */
class IOUtils {

    private static final byte[] EMPTY_BUF = new byte[0];

    private static final ObjectIdentifier GSS_KRB5_MECH_OBJECT_IDENTIFIER;

    static {
        try {
            GSS_KRB5_MECH_OBJECT_IDENTIFIER = ObjectIdentifier.of(CustomKrb5MechFactory.GSS_KRB5_MECH_OID.toString());
        } catch (IOException e) {
            throw new IllegalStateException("Failed to get OID", e);
        }
    }

    /**
     * Read a GSS token from the input, designed for the specific needs of
     * {@link CustomGSSContextSpiImpl#initSecContext(InputStream, int)} and
     * {@link CustomGSSContextSpiImpl#acceptSecContext(InputStream, int)}.
     * <p/>
     * This method is greatly simplified, in its current state, it's only capable of reading streams with known sizes,
     * or whose contents are exactly one complete GSS token, which for this particular application is inferred from
     * whether the type of the stream is {@link ByteArrayInputStream}. A complete solution was abandoned due to the
     * following reasons:
     * <ul>
     *     <li>it didn't work correctly in some edge cases</li>
     *     <li>in the years since our library has been in production, we haven't seen an attempt to use this method in
     *     a way its current state doesn't support</li>
     *     <li>these streaming methods in JGSS are deprecated for removal in Java 11 due to their unreliability:
     *     https://bugs.openjdk.java.net/browse/JDK-8202953</li>
     * </ul>
     * <p/>
     * This method also includes a workaround for a peculiar behavior of the JVM: knowing the length of the token (the
     * {@code mechTokenLen} parameter being non-negative) implies the header has already been read (that's the only way
     * to tell) which also means consumed (removed from the stream) but our downstream needs the header too, so this
     * method puts it back.
     *
     * @param is the input to read from, if the {@code mechTokenLen} argument is unspecified (negative), this must
     *     be a {@link ByteArrayInputStream} to indicate it has been constructed from a full token in a byte array.
     * @param mechTokenLen the length of the token to read, -1 if unknown and the whole buffer should be read
     * @return the token
     * @throws IOException if reading fails or the token is malformed
     */
    static byte[] readToken(InputStream is, int mechTokenLen) throws IOException, GSSException {
        if (mechTokenLen >= 0) {
            // NOTE: on the first call to CustomGSSContextSpiImpl.acceptSecContext(java.io.InputStream, int),
            // sun.security.jgss.GSSContextImpl#acceptSecContext(InputStream, OutputStream) strips off the header, so we
            // need to put it back. On further calls, it doesn't, so it can't tell the token size either, passing -1. In
            // this case we just have to consume the whole token.
            // In CustomGSSContextSpiImpl.initSecContext(java.io.InputStream, int) we always have to read the whole
            // token.
            GSSHeader gssHeader = new GSSHeader(GSS_KRB5_MECH_OBJECT_IDENTIFIER, mechTokenLen);
            ByteArrayOutputStream baos = new ByteArrayOutputStream(1024);
            gssHeader.encode(baos);
            baos.write(readBytes(is, mechTokenLen));
            return baos.toByteArray();
        } else {
            if (is instanceof ByteArrayInputStream) {
                return readBytes(is, is.available());
            } else {
                throw new GSSException(GSSException.UNAVAILABLE, -1, "Streaming methods are not supported");
            }
        }
    }

    /**
     * Read exactly <code>numRead</code> bytes in a new byte array. An {@link EOFException} is thrown if the
     * <code>source</code> ends earlier.
     */
    private static byte[] readBytes(InputStream source, int numRead) throws IOException {
        if (numRead == 0) {
            return EMPTY_BUF;
        }

        byte[] read = new byte[numRead];

        int len = source.read(read, 0, numRead);

        if (len < numRead) {
            throw new EOFException("Premature end of stream");
        }

        return read;
    }

    private IOUtils() {
        // prevent instantiation
    }
}
