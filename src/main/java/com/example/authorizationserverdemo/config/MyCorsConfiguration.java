package com.example.authorizationserverdemo.config;

import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@Component
public class MyCorsConfiguration implements CorsConfigurationSource {
    @Override
    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowedMethods(List.of("*"));
        configuration.setAllowedOrigins(List.of("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(1800L);

        return configuration;
    }
}
