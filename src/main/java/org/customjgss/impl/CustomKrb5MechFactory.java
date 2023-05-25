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
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import sun.security.jgss.GSSCaller;
import sun.security.jgss.spi.GSSContextSpi;
import sun.security.jgss.spi.GSSCredentialSpi;
import sun.security.jgss.spi.GSSNameSpi;
import sun.security.jgss.spi.MechanismFactory;

/**
 * JGSS-compatible KRB5 mechanism implementation for demonstration purposes. Use via the
 * {@link CustomKerberosJgssProvider}.
 */
public class CustomKrb5MechFactory implements MechanismFactory {

    static final Oid GSS_KRB5_MECH_OID;

    static final Oid NT_GSS_KRB5_PRINCIPAL;

    static {
        try {
            GSS_KRB5_MECH_OID = new Oid("1.2.840.113554.1.2.2");
            NT_GSS_KRB5_PRINCIPAL = new Oid("1.2.840.113554.1.2.2.1");
        } catch (GSSException e) {
            throw new IllegalStateException("Failed to initialize OIDs", e);
        }
    }

    private static final Oid[] nameTypes = new Oid[] {
        GSSName.NT_USER_NAME, GSSName.NT_HOSTBASED_SERVICE, GSSName.NT_EXPORT_NAME, NT_GSS_KRB5_PRINCIPAL};

    /**
     * JGSS-compatible KRB5 mechanism implementation for demonstration purposes. Use via the
     * {@link CustomKerberosJgssProvider}.
     *
     * @param caller unused, required for reflective calls by the infrastructure
     */
    public CustomKrb5MechFactory(GSSCaller caller) {
        // no-op
    }

    @Override
    public Oid getMechanismOid() {
        return GSS_KRB5_MECH_OID;
    }

    @Override
    public Provider getProvider() {
        return CustomKerberosJgssProvider.INSTANCE;
    }

    @Override
    public Oid[] getNameTypes() {
        return nameTypes;
    }

    private CustomGSSNameSpiImpl convertName(GSSNameSpi name) throws GSSException {
        if (name == null) {
            return null;
        }

        if (name instanceof CustomGSSNameSpiImpl) {
            return (CustomGSSNameSpiImpl) name;
        }

        return new CustomGSSNameSpiImpl(name.toString(), name.getStringNameType());
    }

    private CustomGSSCredentialSpiImpl convertCredentials(GSSCredentialSpi credentials) throws GSSException {
        if (credentials == null) {
            return null;
        }

        if (credentials instanceof CustomGSSCredentialSpiImpl) {
            return (CustomGSSCredentialSpiImpl) credentials;
        }

        return new CustomGSSCredentialSpiImpl(convertName(credentials.getName()), credentials.getInitLifetime(),
            credentials.getAcceptLifetime(), getUsage(credentials));
    }

    private int getUsage(GSSCredentialSpi credentials) throws GSSException {
        if (credentials.isAcceptorCredential() && credentials.isInitiatorCredential()) {
            return GSSCredential.INITIATE_AND_ACCEPT;
        } else if (credentials.isAcceptorCredential()) {
            return GSSCredential.ACCEPT_ONLY;
        } else if (credentials.isInitiatorCredential()) {
            return GSSCredential.INITIATE_ONLY;
        } else {
            throw new GSSException(GSSException.DEFECTIVE_CREDENTIAL, -1,
                "Provided credential is neither an initiator nor an acceptor");
        }
    }

    @Override
    public GSSCredentialSpi getCredentialElement(GSSNameSpi name, int initLifetime, int acceptLifetime, int usage)
        throws GSSException {
        return new CustomGSSCredentialSpiImpl(convertName(name), initLifetime, acceptLifetime, usage);
    }

    @Override
    public GSSNameSpi getNameElement(String nameStr, Oid nameType) throws GSSException {
        return new CustomGSSNameSpiImpl(nameStr, nameType);
    }

    @Override
    public GSSNameSpi getNameElement(byte[] name, Oid nameType) throws GSSException {
        return new CustomGSSNameSpiImpl(name, nameType);
    }

    @Override
    public GSSContextSpi getMechanismContext(GSSNameSpi peer, GSSCredentialSpi myInitiatorCred, int lifetime)
        throws GSSException {
        return new CustomGSSContextSpiImpl(convertName(peer), convertCredentials(myInitiatorCred), lifetime);
    }

    @Override
    public GSSContextSpi getMechanismContext(GSSCredentialSpi myAcceptorCred) throws GSSException {
        return new CustomGSSContextSpiImpl(convertCredentials(myAcceptorCred));
    }

    @Override
    public GSSContextSpi getMechanismContext(byte[] exportedContext) throws GSSException {
        return new CustomGSSContextSpiImpl(exportedContext);
    }
}
