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

import org.customjgss.CustomKerberosJgssProvider;
import java.security.Provider;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;
import sun.security.jgss.spi.GSSCredentialSpi;
import sun.security.jgss.spi.GSSNameSpi;

// implementation classes - a real implementation wouldn't use these
import sun.security.jgss.krb5.Krb5MechFactory;

class CustomGSSCredentialSpiImpl implements GSSCredentialSpi {

    // Instead of this, a real implementation would be in-place, or delegate to native code
    private final GSSCredentialSpi delegate;

    CustomGSSCredentialSpiImpl(GSSNameSpi name, int initLifetime, int acceptLifetime, int usage) throws GSSException {
        delegate = new Krb5MechFactory(null).getCredentialElement(name, initLifetime, acceptLifetime, usage);
    }


    @Override
    public Provider getProvider() {
        return CustomKerberosJgssProvider.INSTANCE;
    }

    @Override
    public GSSNameSpi getName() throws GSSException {
        return delegate.getName();
    }

    @Override
    public int getInitLifetime() throws GSSException {
        return delegate.getInitLifetime();
    }

    @Override
    public int getAcceptLifetime() throws GSSException {
        return delegate.getAcceptLifetime();
    }

    @Override
    public boolean isInitiatorCredential() throws GSSException {
        return delegate.isInitiatorCredential();
    }

    @Override
    public boolean isAcceptorCredential() throws GSSException {
        return delegate.isAcceptorCredential();
    }

    @Override
    public Oid getMechanism() {
        return delegate.getMechanism();
    }

    @Override
    public GSSCredentialSpi impersonate(GSSNameSpi gssNameSpi) throws GSSException {
        return delegate.impersonate(gssNameSpi);
    }

    @Override
    public void dispose() throws GSSException {
        delegate.dispose();
    }

    @Override
    public String toString() {
        return delegate.toString();
    }
}
