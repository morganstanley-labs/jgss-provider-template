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
package example.provider;

import example.provider.impl.CustomKrb5MechFactory;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A security {@link Provider} for KRB5 and SPNEGO mechanisms meant to replace {@link sun.security.jgss.SunProvider}.
 * <p/>
 * This version is created for demonstration purposes, it delegates internally to the builtin classes. The provided
 * SPNEGO implementation is the same one that the {@link sun.security.jgss.SunProvider} provides, because replacing it
 * is not necessary.
 * <p/>
 * Calling the {@link #install()} method replaces the builtin {@link sun.security.jgss.SunProvider} with this one in
 * {@link Security}.
 */
public final class CustomKerberosJgssProvider extends Provider {

    private static final Logger LOGGER = Logger.getLogger(CustomKerberosJgssProvider.class.getCanonicalName());

    public static final String NAME_SUNJGSS = "SunJGSS";

    public static final String NAME_SUN_NATIVE_JGSS = "SunNativeGSS";

    // NOTE: in a native provider, we'd use the Sun native provider's name, because this changes the calling code's
    // behavior in a way that's easier to work with. (See `mechCtxt.getProvider().getName().equals("SunNativeGSS")`
    // conditions in sun.security.jgss.GSSContextImpl.) Since we now only delegate to the regular provider, we don't
    // do this to match its expectations.
    public static final String NAME_CUSTOM_JGSS = "CustomJGSS";

    private static final String INFO = "Custom JGSS (Kerberos v5, SPNEGO)";

    /**
     * Only public for the sake of certain infrastructure code that uses reflection to get static instances of
     * registered {@link Provider}s. Might be null if initialization has failed.
     * <p/>
     * Prefer using {@link #getInstance()} which checks for initialization errors as well.
     */
    public static final CustomKerberosJgssProvider INSTANCE;

    private static Throwable initThrowable;

    private static boolean installed;

    static {
        CustomKerberosJgssProvider instance = null;
        try {
            instance = new CustomKerberosJgssProvider(false);
        } catch (Throwable t) {
            initThrowable = t;
        }
        INSTANCE = instance;
    }

    // guarded by Security.class
    private static void ensureInitialized() {
        // Throw any error from the class init, or previous attempts
        checkForInitError();
        // No separate check needed, because if the below fails, the above will throw the next time
        try {
            // Trigger init and throw anything that comes out of it
            new CustomKrb5MechFactory(null);
        } catch (Throwable t) {
            initThrowable = t;
        }
        // Throw the above error if there was any
        checkForInitError();
    }

    private static void checkForInitError() {
        if (initThrowable != null) {
            if (initThrowable instanceof Error) {
                throw (Error) initThrowable;
            } else if (initThrowable instanceof RuntimeException) {
                throw (RuntimeException) initThrowable;
            } else {
                throw new IllegalStateException(initThrowable);
            }
        }
    }

    /**
     * Get the default instance of this provider. Same as {@link #INSTANCE} but checks for initialization errors before
     * returning it, thus it cannot return null. It also installs the provider if it's not yet installed, like the
     * default constructor.
     */
    public static CustomKerberosJgssProvider getInstance() {
        install();
        return INSTANCE;
    }

    /**
     * Replace the {@link sun.security.jgss.SunProvider} with an instance of this one in {@link Security}. All further
     * calls to this method are a no-op.
     */
    public static void install() {
        // Don't try to install if we know it's going to fail
        checkForInitError();
        if (!installed) {
            synchronized (Security.class) {
                if (!installed) {
                    LOGGER.info(() -> "Attempting to install " + CustomKerberosJgssProvider.class.getCanonicalName()
                        + " in " + Security.class.getCanonicalName());
                    try {
                        String jaasTicketCachePath = LoginModuleUtils.fakeCredentialsCache();
                        ensureInitialized();
                        if (!isReallyInstalled()) {
                            Security.removeProvider(NAME_SUNJGSS);
                            Security.removeProvider(NAME_SUN_NATIVE_JGSS);
                            Security.removeProvider(NAME_CUSTOM_JGSS);
                            Security.insertProviderAt(INSTANCE, 1);
                            Configurations.setTicketCachePathForJaasLogin(jaasTicketCachePath);
                            LOGGER.info(
                                () -> "Successfully installed " + CustomKerberosJgssProvider.class.getCanonicalName()
                                    + " in " + Security.class.getCanonicalName());
                        } else {
                            // Still need to do this to make sure JAAS Login works as well
                            Configurations.setTicketCachePathForJaasLogin(jaasTicketCachePath);
                            LOGGER.info(
                                () -> "Skipped installing " + CustomKerberosJgssProvider.class.getCanonicalName()
                                    + " in " + Security.class.getCanonicalName()
                                    + " because it was found to be already "
                                    + "installed externally");
                        }
                        installed = true;
                        // Don't log "Skipped installing"... at the end of the method
                        return;
                    } catch (Throwable t) {
                        LOGGER.log(Level.SEVERE, t, () -> "Failed to install "
                            + CustomKerberosJgssProvider.class.getCanonicalName() + " in "
                            + Security.class.getCanonicalName());
                        throw t;
                    }
                }
            }
        }

        LOGGER.finer(() -> "Skipped installing " + CustomKerberosJgssProvider.class.getCanonicalName() + " in "
            + Security.class.getCanonicalName() + " because it's already installed");
    }

    /**
     * Tells whether this provider has been installed
     */
    public static boolean isInstalled() {
        return installed || isReallyInstalled();
    }

    private static boolean isReallyInstalled() {
        // Since we may reuse the name of the native provider, it's not enough to just check that we are installed, we
        // also check that the default is not installed. If our provider was added via a security config without
        // removing the default provider (which is a bad idea anyway), we'll reinstall it as a result.
        return Security.getProvider(NAME_CUSTOM_JGSS) != null && Security.getProvider(NAME_SUNJGSS) == null;
    }

    /**
     * Only public for the sake of certain infrastructure code that uses reflection to create instances of registered
     * {@link Provider}s.
     * <p/>
     * Prefer using {@link #getInstance()}
     * <p/>
     * Ensures the provider is installed.
     */
    public CustomKerberosJgssProvider() {
        // It must be already installed, but we have to update the state and do the additional installation tasks
        this(true);
    }

    private CustomKerberosJgssProvider(boolean ensureInstalled) {
        super(NAME_CUSTOM_JGSS, 1.8d, INFO);

        if (ensureInstalled) {
            install();
        }

        AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            put("GssApiMechanism.1.2.840.113554.1.2.2", CustomKrb5MechFactory.class.getName());
            // NOTE: the built-in SPNEGO provider uses the registered KRB5 provider for generating tokens
            // One minor issue with it is that it returns the SunProvider from its getProvider() method, but
            // that appears not to cause issues.
            put("GssApiMechanism.1.3.6.1.5.5.2", "sun.security.jgss.spnego.SpNegoMechFactory");
            return null;
        });
    }
}
