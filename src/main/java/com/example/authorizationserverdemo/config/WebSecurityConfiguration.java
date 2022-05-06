package com.example.authorizationserverdemo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;

@EnableWebSecurity
public class WebSecurityConfiguration {

    @Autowired
    private CorsConfigurationSource myCorsConfiguration;

    @Bean
    public SecurityFilterChain configureSecurityFilterChain(HttpSecurity http) throws Exception {
        /*
        Here, we are configuring API protection. We say, "every request should be
        authenticated, except '/docs'"
        */

        http.cors().configurationSource(myCorsConfiguration)
//              maybe we'll need to prevent CSRF if we get 403 Forbidden on POST/DELETE requests
//                .and().csrf().disable()
//              or create CSRF token
//                .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and().authorizeHttpRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())  // request user authentication for all http requests
                .formLogin(Customizer.withDefaults());  // enabling authentication with login form; to change login form, replace Customizer with your custom class or a string with the path to the login page

        return http.build();
    }

    @Autowired
    private AuthenticationProvider customAuthenticationProvider;

    @Autowired
    public void configureAuthenticationManagerBuilder(AuthenticationManagerBuilder auth) {
        /*
        We are configuring which authentication provider (which uses our custom UserDetailsService and PasswordEncoder) this app is going to use.
         */
        auth.authenticationProvider(customAuthenticationProvider);
    }

}
