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

import com.sun.security.jgss.InquireType;
import example.provider.Configurations;
import example.provider.CustomKerberosJgssProvider;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Provider;
import org.ietf.jgss.ChannelBinding;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;
import sun.security.jgss.spi.GSSContextSpi;
import sun.security.jgss.spi.GSSCredentialSpi;
import sun.security.jgss.spi.GSSNameSpi;

// implementation classes - a real implementation wouldn't use these
import sun.security.jgss.krb5.Krb5MechFactory;

class CustomGSSContextSpiImpl implements GSSContextSpi {

    static {
        // A real native provider would here inject the real ticket cache path from Configurations.getTicketCachePath()
        // into the JNI code. Since we're using the regular provider here which needs it in the login module, we'll now
        // undo the faking.
        Configurations.setTicketCachePathForJaasLogin(Configurations.getTicketCachePath());
    }

    // Instead of this, a real implementation would be in-place, or delegate to native code
    private final GSSContextSpi delegate;

    CustomGSSContextSpiImpl(GSSNameSpi peer, GSSCredentialSpi myInitiatorCred, int lifetime) throws GSSException {
        delegate = new Krb5MechFactory(null).getMechanismContext(peer, myInitiatorCred, lifetime);
    }

    CustomGSSContextSpiImpl(GSSCredentialSpi myAcceptorCred) throws GSSException {
        delegate = new Krb5MechFactory(null).getMechanismContext(myAcceptorCred);
    }

    CustomGSSContextSpiImpl(byte[] exportedContext) throws GSSException {
        delegate = new Krb5MechFactory(null).getMechanismContext(exportedContext);
    }

    @Override
    public Provider getProvider() {
        return CustomKerberosJgssProvider.INSTANCE;
    }

    @Override
    public void requestLifetime(int lifetime) throws GSSException {
        delegate.requestLifetime(lifetime);
    }

    @Override
    public void requestMutualAuth(boolean state) throws GSSException {
        delegate.requestMutualAuth(state);
    }

    @Override
    public void requestReplayDet(boolean state) throws GSSException {
        delegate.requestReplayDet(state);
    }

    @Override
    public void requestSequenceDet(boolean state) throws GSSException {
        delegate.requestSequenceDet(state);
    }

    @Override
    public void requestCredDeleg(boolean state) throws GSSException {
        delegate.requestCredDeleg(state);
    }

    @Override
    public void requestAnonymity(boolean state) throws GSSException {
        delegate.requestAnonymity(state);
    }

    @Override
    public void requestConf(boolean state) throws GSSException {
        delegate.requestConf(state);
    }

    @Override
    public void requestInteg(boolean state) throws GSSException {
        delegate.requestInteg(state);
    }

    @Override
    public void requestDelegPolicy(boolean state) throws GSSException {
        delegate.requestDelegPolicy(state);
    }

    @Override
    public void setChannelBinding(ChannelBinding channelBinding) throws GSSException {
        delegate.setChannelBinding(channelBinding);
    }

    @Override
    public boolean getCredDelegState() {
        return delegate.getCredDelegState();
    }

    @Override
    public boolean getMutualAuthState() {
        return delegate.getMutualAuthState();
    }

    @Override
    public boolean getReplayDetState() {
        return delegate.getReplayDetState();
    }

    @Override
    public boolean getSequenceDetState() {
        return delegate.getSequenceDetState();
    }

    @Override
    public boolean getAnonymityState() {
        return delegate.getAnonymityState();
    }

    @Override
    public boolean getDelegPolicyState() {
        return delegate.getDelegPolicyState();
    }

    @Override
    public boolean isTransferable() throws GSSException {
        return delegate.isTransferable();
    }

    @Override
    public boolean isProtReady() {
        return delegate.isProtReady();
    }

    @Override
    public boolean isInitiator() {
        return delegate.isInitiator();
    }

    @Override
    public boolean getConfState() {
        return delegate.getConfState();
    }

    @Override
    public boolean getIntegState() {
        return delegate.getIntegState();
    }

    @Override
    public int getLifetime() {
        return delegate.getLifetime();
    }

    @Override
    public boolean isEstablished() {
        return delegate.isEstablished();
    }

    @Override
    public GSSNameSpi getSrcName() throws GSSException {
        return delegate.getSrcName();
    }

    @Override
    public GSSNameSpi getTargName() throws GSSException {
        return delegate.getTargName();
    }

    @Override
    public Oid getMech() throws GSSException {
        return delegate.getMech();
    }

    @Override
    public GSSCredentialSpi getDelegCred() throws GSSException {
        return delegate.getDelegCred();
    }

    @Override
    public byte[] initSecContext(InputStream is, int mechTokenSize) throws GSSException {
        // NOTE: in a real implementation, we'd read a byte array using IOUtils.readToken(InputStream, int), then
        // hand it over to a native method, but in this case we just call the delegate. Also, the provider would
        // have to be called "SunNativeGSS", otherwise the returned token is also modified by the calling code.
        return delegate.initSecContext(is, mechTokenSize);
    }

    @Override
    public byte[] acceptSecContext(InputStream is, int mechTokenSize) throws GSSException {
        // NOTE: in a real implementation, we'd read a byte array using IOUtils.readToken(InputStream, int), then
        // hand it over to a native method, but in this case we just call the delegate. Also, the provider would
        // have to be called "SunNativeGSS", otherwise the returned token is also modified by the calling code.
        return delegate.acceptSecContext(is, mechTokenSize);
    }

    @Override
    public int getWrapSizeLimit(int qop, boolean confReq, int maxTokSize) throws GSSException {
        return delegate.getWrapSizeLimit(qop, confReq, maxTokSize);
    }

    @Override
    public void wrap(InputStream is, OutputStream os, MessageProp msgProp) throws GSSException {
        // NOTE: this may be left unimplemented in a real implementation
        delegate.wrap(is, os, msgProp);
    }

    @Override
    public byte[] wrap(byte[] inBuf, int offset, int len, MessageProp msgProp) throws GSSException {
        return delegate.wrap(inBuf, offset, len, msgProp);
    }

    @Override
    public void unwrap(InputStream is, OutputStream os, MessageProp msgProp) throws GSSException {
        // NOTE: this may be left unimplemented in a real implementation
        delegate.unwrap(is, os, msgProp);
    }

    @Override
    public byte[] unwrap(byte[] inToken, int offset, int len, MessageProp msgProp) throws GSSException {
        return delegate.unwrap(inToken, offset, len, msgProp);
    }

    @Override
    public void getMIC(InputStream is, OutputStream os, MessageProp msgProp) throws GSSException {
        // NOTE: this may be left unimplemented in a real implementation
        delegate.getMIC(is, os, msgProp);
    }

    @Override
    public byte[] getMIC(byte[] inBuf, int offset, int len, MessageProp msgProp) throws GSSException {
        return delegate.getMIC(inBuf, offset, len, msgProp);
    }

    @Override
    public void verifyMIC(InputStream is, InputStream msgStr, MessageProp msgProp) throws GSSException {
        // NOTE: this may be left unimplemented in a real implementation
        delegate.verifyMIC(is, msgStr, msgProp);
    }

    @Override
    public void verifyMIC(byte[] inTok, int tokOffset, int tokLen, byte[] inMsg, int msgOffset, int msgLen,
        MessageProp msgProp) throws GSSException {

        delegate.verifyMIC(inTok, tokOffset, tokLen, inMsg, msgOffset, msgLen, msgProp);
    }

    @Override
    public byte[] export() throws GSSException {
        // NOTE: this may be left unimplemented in a real implementation
        return delegate.export();
    }

    @Override // Java 8
    public Object inquireSecContext(InquireType type) throws GSSException {
        // NOTE: see NOTE on Java 11 variant below
        return delegate.inquireSecContext(type);
    }

    // @Override // Java 11
    public Object inquireSecContext(String type) throws GSSException {
        // NOTE: in a real implementation, this would be implemented and called by the Java 8 variant above, but it may
        // also be left unimplemented (e.g. getting the private key is not even possible on Windows)
        throw new GSSException(GSSException.UNAVAILABLE, -1, "Not implemented");
    }

    @Override
    public void dispose() throws GSSException {
        // NOTE: this is very important for a native implementation, should be called by a cleaner or finalizer as well
        delegate.dispose();
    }

    @Override
    public String toString() {
        return delegate.toString();
    }
}
