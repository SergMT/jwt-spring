package com.programandoenjava.jwt.config;

import com.programandoenjava.jwt.auth.repository.Token;
import com.programandoenjava.jwt.auth.repository.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final TokenRepository tokenRepository;

    Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    public SecurityFilterChain securityFilterChain(final HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(req ->
                        req.requestMatchers("/auth/**")
                                .permitAll()
                                .anyRequest()
                                .authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(logout ->
                        logout.logoutUrl("/auth/logout")
                                .addLogoutHandler(this::logout)
                                .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext())
                )
        ;

        return http.build();
    }

    private void logout(
        final HttpServletRequest request, final HttpServletResponse response,
        final Authentication authentication
) {
    logger.info("Entering logout handler...");
    final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
    logger.info("Authorization Header: {}", authHeader);

    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
        logger.info("Missing or invalid Authorization header");
        return;
    }

    final String jwt = authHeader.substring(7);
    logger.info("JWT extracted: {}", jwt);
    
    final Token storedToken = tokenRepository.findByToken(jwt).orElse(null);
    if (storedToken != null) {
        logger.info("Marking token as expired and revoked");
        storedToken.setIsExpired(true);
        storedToken.setIsRevoked(true);
        tokenRepository.save(storedToken);
        logger.info("Token updated in database");
    } else {
        logger.info("Token not found in database");
    }

    SecurityContextHolder.clearContext();
}


    // private void logout(
    //         final HttpServletRequest request, final HttpServletResponse response,
    //         final Authentication authentication
    // ) {
        
    //     logger.info("Entra a logout");
    //     logger.info("Request: {}", request);
    //     logger.info("Response: {}", response);
    //     logger.info("Authentication: {}", authentication);

    //     final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
    //     if (authHeader == null || !authHeader.startsWith("Bearer ")) {
    //         return;
    //     }

    //     final String jwt = authHeader.substring(7);
    //     final Token storedToken = tokenRepository.findByToken(jwt)
    //             .orElse(null);
    //     if (storedToken != null) {
    //         storedToken.setIsExpired(true);
    //         storedToken.setIsRevoked(true);
    //         tokenRepository.save(storedToken);
    //         SecurityContextHolder.clearContext();
    //     }
    // }
}
