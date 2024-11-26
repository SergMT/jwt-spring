package com.programandoenjava.jwt.config;

import com.programandoenjava.jwt.auth.repository.Token;
import com.programandoenjava.jwt.auth.repository.TokenRepository;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
                        req.requestMatchers("/", "/auth/**", "/css/**", 
                                        "/js/**", "/images/**").permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(logout ->
                        logout.logoutUrl("/auth/logout")
                        .addLogoutHandler(this::logout)
                        .logoutSuccessHandler((request, response, authentication) -> {
                            logger.info("Logout successful");
                            SecurityContextHolder.clearContext();
                }));

        return http.build();
    }

    private void logout(
        final HttpServletRequest request,
        final HttpServletResponse response,
        final Authentication authentication) {

        logger.info("Entering logout handler...");

        // Extract JWT token from cookies
        final Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            logger.info("No cookies found in request");
            return;
        }

        String jwt = null;
        for (Cookie cookie : cookies) {
            if ("jwt".equals(cookie.getName())) {
                jwt = cookie.getValue();
                break;
            }
        }

        if (jwt == null) {
            logger.info("JWT token not found in cookies");
            return;
        }

        logger.info("JWT extracted from cookie: {}", jwt);

        // Revoke the token in the database
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

        // Remove the JWT cookie
        logger.info("Removing JWT cookie");
        Cookie cookie = new Cookie("jwt", null);
        cookie.setHttpOnly(true);
        cookie.setSecure(false); // Set this to true in production
        cookie.setPath("/");
        cookie.setMaxAge(0); // Marks the cookie for deletion
        response.addCookie(cookie);

        SecurityContextHolder.clearContext();
    }

}
