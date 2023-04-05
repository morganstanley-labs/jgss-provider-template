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
package example.provider.impl;

import example.provider.CustomKerberosJgssProvider;
import java.security.Provider;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;
import sun.security.jgss.spi.GSSNameSpi;

// implementation classes - a real implementation wouldn't use these
import sun.security.jgss.krb5.Krb5MechFactory;

class CustomGSSNameSpiImpl implements GSSNameSpi {

    // Instead of this, a real implementation would be in-place, or delegate to native code
    private final GSSNameSpi delegate;

    CustomGSSNameSpiImpl(byte[] name, Oid nameType) throws GSSException {
        delegate = new Krb5MechFactory(null).getNameElement(name, nameType);
    }

    CustomGSSNameSpiImpl(String name, Oid nameType) throws GSSException {
        delegate = new Krb5MechFactory(null).getNameElement(name, nameType);
    }

    @Override
    public Provider getProvider() {
        return CustomKerberosJgssProvider.INSTANCE;
    }


    @Override
    public int hashCode() {
        return delegate.hashCode();
    }

    @Override
    public boolean equals(GSSNameSpi other) throws GSSException {
        return delegate.equals(other);
    }

    @Override
    public boolean equals(Object other) {
        return delegate.equals(other);
    }

    @Override
    public byte[] export() throws GSSException {
        return delegate.export();
    }

    @Override
    public Oid getMechanism() {
        return delegate.getMechanism();
    }

    @Override
    public Oid getStringNameType() {
        return delegate.getStringNameType();
    }

    @Override
    public boolean isAnonymousName() {
        return delegate.isAnonymousName();
    }

    @Override
    public String toString() {
        return delegate.toString();
    }
}
