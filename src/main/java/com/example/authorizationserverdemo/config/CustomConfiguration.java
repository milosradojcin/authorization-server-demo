package com.example.authorizationserverdemo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;

import java.util.Set;
import java.util.stream.Collectors;

@Configuration
public class CustomConfiguration {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> buildCustomizer() {
        // this method is executed twice: the first time for the access token, and the second time for the id token

        return context -> {
            // if user authorities should be stored in id token, the next line should be:
//          if (context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
            if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
                Authentication principal = context.getPrincipal();
                Set<String> authorities = principal.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
                context.getClaims().claim("user-authorities", authorities);
            }
        };
    }

}
