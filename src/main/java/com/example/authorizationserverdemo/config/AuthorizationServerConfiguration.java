package com.example.authorizationserverdemo.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
public class AuthorizationServerConfiguration {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // manually registering client
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("drivers-id")  // client id which is sent when requesting access token
                .clientSecret(passwordEncoder.encode("drivers-secret"))  // client secret which is sent when requesting access token; try to encode with Password Encoder
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)  // for BASIC, use Basic auth with clientId and clientSecret values
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)  // for using Authorization Code grant type and "response_type=code"
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:8083/login/oauth2/code/drivers-client")  // 127.0.0.1:8083 is the address of your client, drivers-client is the name of your client (in client's application.yml file)
                .redirectUri("http://127.0.0.1:8083/authorized")
                .scope(OidcScopes.OPENID)
                .scope("read")  // custom scope
//                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())  // for Consent
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);  // try with JdbcRegisteredClientRepository
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)  // this method/bean has the highest priority among all other methods/beans of this type (i.e. over WebSecurityConfiguration/configureSecurityFilterChain)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // default security settings; for custom configuration, configure the http object instead of the next line
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        return http.formLogin(Customizer.withDefaults()).build();  // to change login form, replace Customizer with your custom class or a string with the path to the login page
    }

    @Bean
    public ProviderSettings providerSettings() {
        // try using 127.0.0.1 or something else for docker container; auth-server is defined in the C:\Windows\System32\Drivers\etc\hosts file
        return ProviderSettings.builder().issuer("http://auth-server:8081").build();
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        RSAKey rsaKey = generateRsa();  // generating a signing key for tokens
        JWKSet jwkSet = new JWKSet(rsaKey);

        return ((jwkSelector, securityContext) -> jwkSelector.select(jwkSet));
    }

    private static RSAKey generateRsa() throws NoSuchAlgorithmException {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
    }

    private static KeyPair generateRsaKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        return keyPairGenerator.generateKeyPair();
    }

}
