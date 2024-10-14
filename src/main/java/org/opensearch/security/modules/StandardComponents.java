package org.opensearch.security.modules;

import org.opensearch.security.auth.AuthFailureListener;
import org.opensearch.security.auth.HTTPAuthenticator;
import org.opensearch.security.auth.AuthenticationBackend;
import org.opensearch.security.auth.AuthorizationBackend;
import org.opensearch.security.auth.internal.NoOpAuthenticationBackend;
import org.opensearch.security.auth.internal.NoOpAuthorizationBackend;
import org.opensearch.security.auth.limiting.AddressBasedRateLimiter;
import org.opensearch.security.auth.limiting.UserNameBasedRateLimiter;
import org.opensearch.security.http.HTTPBasicAuthenticator;
import org.opensearch.security.http.HTTPClientCertAuthenticator;
import org.opensearch.security.http.HTTPProxyAuthenticator;
//import org.opensearch.security.http.HTTPProxyAuthenticator2;

public class StandardComponents {

    public static final SearchGuardComponentRegistry<AuthenticationBackend> authcBackends = new SearchGuardComponentRegistry<>(
            AuthenticationBackend.class)//
                    .add("noop", NoOpAuthenticationBackend.class)//
                    .add("ldap", "com.floragunn.dlic.auth.ldap.backend.LDAPAuthenticationBackend")//
                    .add("ldap2", "com.floragunn.dlic.auth.ldap2.LDAPAuthenticationBackend2")//
                    .seal();

    public static final SearchGuardComponentRegistry<AuthorizationBackend> authzBackends = new SearchGuardComponentRegistry<>(
            AuthorizationBackend.class)//
                    .add("noop", NoOpAuthorizationBackend.class)//
                    .add("ldap", "com.floragunn.dlic.auth.ldap.backend.LDAPAuthorizationBackend")//
                    .add("ldap2", "com.floragunn.dlic.auth.ldap2.LDAPAuthorizationBackend2")//
                    .seal();

    public static final SearchGuardComponentRegistry<HTTPAuthenticator> httpAuthenticators = new SearchGuardComponentRegistry<>(
            HTTPAuthenticator.class)//
                    .add("basic", HTTPBasicAuthenticator.class)//
                    .add("proxy", HTTPProxyAuthenticator.class)//
//                    .add("proxy2", HTTPProxyAuthenticator2.class)// TODO: IGOR_ON CHANGE
                    .add("clientcert", HTTPClientCertAuthenticator.class)//
                    .add("kerberos", "com.floragunn.dlic.auth.http.kerberos.HTTPSpnegoAuthenticator")//
                    .add("jwt", "com.floragunn.dlic.auth.http.jwt.HTTPJwtAuthenticator")//
                    .add("openid", "com.floragunn.dlic.auth.http.jwt.keybyoidc.HTTPJwtKeyByOpenIdConnectAuthenticator")//
                    .add("saml", "com.floragunn.dlic.auth.http.saml.HTTPSamlAuthenticator")//
                    .seal();

    public static final SearchGuardComponentRegistry<AuthFailureListener> authFailureListeners = new SearchGuardComponentRegistry<>(
            AuthFailureListener.class)//
                    .add("ip", AddressBasedRateLimiter.class)//
                    .add("username", UserNameBasedRateLimiter.class)//
                    .seal();
}
