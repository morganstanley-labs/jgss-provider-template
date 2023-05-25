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
package org.customjgss;

import java.io.File;
import java.io.IOException;
import java.util.logging.Logger;
import sun.security.krb5.EncryptedData;
import sun.security.krb5.EncryptionKey;
import sun.security.krb5.KrbException;
import sun.security.krb5.PrincipalName;
import sun.security.krb5.internal.KerberosTime;
import sun.security.krb5.internal.Ticket;
import sun.security.krb5.internal.TicketFlags;
import sun.security.krb5.internal.ccache.Credentials;
import sun.security.krb5.internal.ccache.CredentialsCache;

/**
 * Utilities to work around issues with the {@link com.sun.security.auth.module.Krb5LoginModule} on Windows.
 */
class LoginModuleUtils {

    private static final Logger LOGGER = Logger.getLogger(LoginModuleUtils.class.getCanonicalName());

    private LoginModuleUtils() {
        throw new AssertionError();
    }

    /**
     * {@link com.sun.security.auth.module.Krb5LoginModule} needs to read the krbtgt credentials from somewhere when
     * logging in, but then with a real native provider, nothing actually uses it, so they can be fake. On Win 10 with
     * the Credentials Guard on we can't read the cache, but we can write a fake file to calm down the login module. The
     * login module will have to think that the cache is this file, but the actual implementation has to know the
     * truth.
     * <p/>
     * By default, the fake cache is created in a temp file and its path propagated via the
     * {@link javax.security.auth.login.Configuration} class, but this doesn't always work (the configuration may be
     * overwritten by a 3rd party library, or ignored one way or the other). In that case the workaround is to set the
     * {@code KRB5CCNAME} env var to a writable file and tell this library (via {@link Configurations#isFakeKrb5Cc()})
     * to put a fake cache there, since this env var's value is always respected (at least in our experience). In this
     * case, the actual provider has to still know where the real credential cache is. In practice this method is only
     * used on Windows where the SSPI API is used, and that by nature uses the OS's builtin cache, so this will not be a
     * problem then. If a file should be used, we have to assume it's some default the provider will know about.
     * <p/>
     * Note that in this demo implementation we're using the regular provider ultimately, which needs the real cache, so
     * we reset the fake cache in the static init of CustomGSSContextSpiImpl.
     */
    static String fakeCredentialsCache() {
        if (isLsa(Configurations.getTicketCachePath())) {
            // The configured ticket cache is an in-memory one, so we create the fake cache in a temp file and propagate
            // its path via the javax.security.auth.login.Configuration class
            try {
                File ccFile = File.createTempFile("krb5_cc", "_fake");
                ccFile.deleteOnExit();
                String ccFilePath = ccFile.getAbsolutePath();

                createFakeCredentialsCacheAt(ccFilePath);
                return ccFilePath;
            } catch (Exception e) {
                throw new IllegalStateException("Failed to create dummy credentials cache in temp file for JAAS Login",
                    e);
            }
        } else {
            // The configured ticket cache is a file - if it's a real file ticket cache we don't need to (and shouldn't
            // even) fake it. If we're told (via `Configurations.isFakeKrb5Cc()`) that it's just a handpicked location
            // for the fake cache, we do though. In this case we have to indicate to the provider that this is not the
            // real cache.
            String ccFilePath = Configurations.getTicketCachePath();
            if (Configurations.isFakeKrb5Cc()) {
                try {
                    createFakeCredentialsCacheAt(ccFilePath);

                    // use default credentials cache instead of the fake in the implementation
                    Configurations.setTicketCachePath(null);
                    return ccFilePath;
                } catch (Exception e) {
                    throw new IllegalStateException("Failed to create dummy credentials cache at specific location \""
                        + ccFilePath + "\" for JAAS Login", e);
                }
            } else {
                LOGGER.info(() -> "Skipped creating fake credentials cache for JAAS Login - will use " + ccFilePath);
                return ccFilePath;
            }
        }
    }

    private static void createFakeCredentialsCacheAt(String path) throws IOException, KrbException {
        // CredentialsCache doesn't tell what's wrong when it breaks, so check potential issues up front
        File ccFile = new File(path);

        if (!ccFile.exists()) {
            ccFile = ccFile.getParentFile();

            if (!ccFile.isDirectory()) {
                throw throwIOExceptionForFileCreationFailure(path, "parent doesn't exist or is not a directory");
            }
        }

        if (!ccFile.canWrite()) {
            throw throwIOExceptionForFileCreationFailure(path,
                "this process doesn't have permission to modify or create it");
        }

        String myPrincipalStr = Configurations.getUserPrincipal();
        PrincipalName myPrincipal = new PrincipalName(myPrincipalStr);
        PrincipalName krbtgtPrincipal = new PrincipalName(
            "krbtgt/" + myPrincipalStr.substring(myPrincipalStr.indexOf('@') + 1));

        KerberosTime start = KerberosTime.now();
        long tenYears = 3653L * 24L * 60L * 60L * 1000L;
        // NOTE: 100 years overflows, we hope 10 doesn't
        KerberosTime end = new KerberosTime(start.getTime() + tenYears);

        EncryptionKey encryptionKey =
            new EncryptionKey(new byte[0], EncryptedData.ETYPE_AES128_CTS_HMAC_SHA1_96, null);
        TicketFlags ticketFlags = new TicketFlags();
        Ticket ticket = new Ticket(krbtgtPrincipal,
            new EncryptedData(EncryptedData.ETYPE_AES128_CTS_HMAC_SHA1_96, null, new byte[0]));

        Credentials fakeKrbtgtCredentials = new Credentials(
            myPrincipal,
            krbtgtPrincipal,
            encryptionKey,
            start,
            start,
            end,
            end,
            false,
            ticketFlags,
            null,
            null,
            ticket,
            null
        );

        CredentialsCache cc = CredentialsCache.create(myPrincipal, path);

        if (cc == null) {
            throw throwIOExceptionForFileCreationFailure(path, "CredentialsCache.create() returned null");
        }

        cc.update(fakeKrbtgtCredentials);
        cc.save();

        LOGGER.info(() -> "Created fake credentials cache for JAAS Login at " + path + " with "
            + fakeKrbtgtCredentials.setKrbCreds());
    }

    private static boolean isLsa(String ticketCachePath) {
        return Configurations.isWindows()
            && (ticketCachePath == null || ticketCachePath.toUpperCase().startsWith("MSLSA:"));
    }

    private static IOException throwIOExceptionForFileCreationFailure(String path, String reason) throws IOException {
        throw new IOException("Cannot create credentials cache file at " + path + ", " + reason);
    }
}
