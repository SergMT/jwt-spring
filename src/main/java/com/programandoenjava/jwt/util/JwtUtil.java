package com.programandoenjava.jwt.util;

import org.springframework.http.HttpHeaders;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

public class JwtUtil {

    public static String extractJwtFromRequest(HttpServletRequest request) {
        // Check Authorization header first
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7); // Extract the token
        }

        // Fallback to checking cookies
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("jwt".equals(cookie.getName())) {
                    return cookie.getValue(); // Extract token from cookie
                }
            }
        }

        return null; // No JWT found
    }
}
