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

import com.sun.security.auth.module.Krb5LoginModule;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import sun.security.krb5.Realm;
import sun.security.krb5.RealmException;

/**
 * Very minimal JAAS config helper class to demonstrate how the fake credential cache would be used + some required
 * utility methods
 */
public class Configurations {

    private static String ticketCachePath = System.getenv("KRB5CCNAME");

    private static String ticketCachePathForJaasLogin = ticketCachePath;

    private static final DecoratedConfiguration configuration;

    static {
        configuration = new DecoratedConfiguration(Configuration.getConfiguration());
        Configuration.setConfiguration(configuration);
    }

    /**
     * Inject the path to a fake ticket cache to be used by {@link Krb5LoginModule#login()} calls.
     */
    public static void setTicketCachePathForJaasLogin(String jaasTicketCachePath) {
        ticketCachePathForJaasLogin = jaasTicketCachePath;
    }

    /**
     * Get the path to the real ticket cache, or null if the platform-specific default should be used.
     */
    public static String getTicketCachePath() {
        return ticketCachePath;
    }

    /**
     * Set the path to the real ticket cache. Pass null if the platform-specific default should be used.
     */
    public static void setTicketCachePath(String path) {
        ticketCachePath = path;
    }

    /**
     * Whether a fake cache should be created at the path indicated by {@link #getTicketCachePath()}.
     */
    public static boolean isFakeKrb5Cc() {
        return Boolean.getBoolean("fake.krb5.cc");
    }

    public static String getUserPrincipal() throws RealmException {
        return System.getProperty("user.name") + "@" + getDefaultRealm();
    }

    public static String getDefaultRealm() throws RealmException {
        return Realm.getDefault().toString();
    }

    public static boolean isWindows() {
        return System.getProperty("os.name").startsWith("Windows");
    }

    private static class DecoratedConfiguration extends Configuration {

        // NOTE: a real implementation may also allow setting the individual login module configurations from code,
        // although that's only really necessary if the standard JGSS provider is used, since a real native provider
        // would usually ignore them. In this minimal demonstration we just ensure the fake ticket cache is
        // appropriately propagated.

        private final Configuration delegate;

        DecoratedConfiguration(Configuration delegate) {
            this.delegate = delegate;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            return decorate(delegate.getAppConfigurationEntry(name));
        }

        private static AppConfigurationEntry[] decorate(AppConfigurationEntry[] original) {
            if (ticketCachePathForJaasLogin == null) {
                return original;
            }

            AppConfigurationEntry[] decorated = new AppConfigurationEntry[original.length];

            for (int i = 0; i < original.length; i++) {
                AppConfigurationEntry entry = original[i];

                if (entry.getLoginModuleName().equals(Krb5LoginModule.class.getSimpleName())) {
                    entry = decorate(entry);
                }

                decorated[i] = entry;
            }

            return decorated;
        }

        private static AppConfigurationEntry decorate(AppConfigurationEntry entry) {
            return new AppConfigurationEntry(entry.getLoginModuleName(), entry.getControlFlag(),
                decorate(entry.getOptions()));
        }

        private static Map<String, ?> decorate(Map<String, ?> options) {
            Map<String, Object> map = new HashMap<>(options);
            map.put("ticketCache", ticketCachePathForJaasLogin);
            return map;
        }
    }
}
