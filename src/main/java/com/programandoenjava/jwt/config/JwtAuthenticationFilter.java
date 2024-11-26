package com.programandoenjava.jwt.config;

import com.programandoenjava.jwt.auth.repository.TokenRepository;
import com.programandoenjava.jwt.auth.service.JwtService;
import com.programandoenjava.jwt.user.User;
import com.programandoenjava.jwt.user.UserRepository;
import com.programandoenjava.jwt.util.JwtUtil;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;
    private final UserRepository userRepository;

    Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        String requestPath = request.getServletPath();
        logger.info("Processing request: {}", requestPath);

        // Allow public routes to proceed without checking for JWT
        if (isPublicRoute(requestPath)) {
            logger.info("Public route accessed: {}", requestPath);
            filterChain.doFilter(request, response);
            return;
        }

        // Extract token using JwtUtil
        final String jwt = JwtUtil.extractJwtFromRequest(request);

        if (jwt == null) {
            logger.warn("JWT token not found in the request. Redirecting to login page.");
            response.sendRedirect("/?message=sessionExpired");
            return; // Stop further processing
        }

        logger.info("JWT Token extracted: {}", jwt);

        final String userEmail = jwtService.extractUsername(jwt);
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (userEmail == null || authentication != null) {
            logger.warn("Invalid JWT or already authenticated");
            filterChain.doFilter(request, response);
            return;
        }

        final UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

        final boolean isTokenValid = tokenRepository.findByToken(jwt)
            .map(token -> !token.getIsExpired() && !token.getIsRevoked())
            .orElse(false);

        if (isTokenValid) {
            final Optional<User> user = userRepository.findByEmail(userEmail);

            if (user.isPresent() && jwtService.isTokenValid(jwt, user.get())) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );

                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                SecurityContextHolder.getContext().setAuthentication(authToken);
                logger.info("Authentication successful for user: {}", userEmail);
            } else {
                logger.warn("Invalid token for user: {}", userEmail);
            }
        } else {
            logger.warn("Token is expired or revoked. Redirecting to login page.");
            response.sendRedirect("/?message=sessionExpired");
            return; // Stop further processing
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Checks if the requested route is public (accessible without authentication).
     *
     * @param requestPath The path of the incoming request.
     * @return true if the route is public, false otherwise.
     */
    private boolean isPublicRoute(String requestPath) {
        return requestPath.equals("/") || requestPath.startsWith("/auth/") || 
               requestPath.startsWith("/css/") || requestPath.startsWith("/js/") ||
               requestPath.startsWith("/images/");
    }

}

