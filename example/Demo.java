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
package example;

import example.provider.CustomKerberosJgssProvider;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;

/**
 * Simple main class demonstrating how a Kerberos client would be used with the provider.
 */
public class Demo {

    public static void main(String[] args) {
        // 1. install the provider
        CustomKerberosJgssProvider.install();

        // 2. use JGSS normally - note that the provider was made for demonstration purposes and haven't been tested in
        // its current form (i.e. it may contain bugs).
        GSSManager gssManager = GSSManager.getInstance();

        try {
            GSSCredential selfCredential = gssManager.createCredential(GSSCredential.INITIATE_ONLY);

            GSSName peerName = gssManager.createName("user/example.com@EXAMPLE.COM", GSSName.NT_HOSTBASED_SERVICE);

            GSSContext context = gssManager.createContext(peerName, null, selfCredential, GSSContext.DEFAULT_LIFETIME);

            byte[] outToken = context.initSecContext(new byte[0], 0, 0);

            // send outToken to the peer, if needed do further rounds until the context is established
        } catch (GSSException e) {
            throw new RuntimeException("Failed to generate Kerberos token", e);
        }
    }
}
