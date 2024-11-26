package com.programandoenjava.jwt.auth.controller;

import com.programandoenjava.jwt.auth.service.AuthService;
import com.programandoenjava.jwt.auth.service.JwtService;
import com.programandoenjava.jwt.user.User;
import com.programandoenjava.jwt.user.UserRepository;
import com.programandoenjava.jwt.util.JwtUtil;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService service;
    private final JwtService jwtService;
    private final UserRepository userRepository;

    Logger logger = LoggerFactory.getLogger(AuthController.class);

    @PostMapping("/register")
    public ResponseEntity<TokenResponse> register(@RequestBody RegisterRequest request) {
        final TokenResponse response = service.register(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> authenticate(@RequestBody AuthRequest request,
        HttpServletResponse response) {
        
        logger.info("Authentication: {}", request);
        final TokenResponse tokenResponse = service.authenticate(request);

        // Add the JWT cookie to the HTTP response
        response.addCookie(tokenResponse.jwtCookie());

        // Prepare a map to return only the tokens (without the cookie)
        Map<String, String> responseBody = Map.of(
            "access_token", tokenResponse.accessToken(),
            "refresh_token", tokenResponse.refreshToken()
        );

        // Return the tokens in the response body
        return ResponseEntity.ok(responseBody);

    }

    @GetMapping("/validate-token")
    public ResponseEntity<Void> validateToken(HttpServletRequest request) {
        logger.info("Validate token request: {}", request);
        String jwt = JwtUtil.extractJwtFromRequest(request);

        if (jwt == null || jwt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build(); // Token missing
        }

        String email = jwtService.extractUsername(jwt); // Extract email from token
        Optional<User> user = userRepository.findByEmail(email);

        if (user.isEmpty() || !jwtService.isTokenValid(jwt, user.get())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build(); // Invalid or expired token
        }

        return ResponseEntity.ok().build(); // Token is valid
    }

    @PostMapping("/refresh-token")
    public TokenResponse refreshToken(
            @RequestHeader(HttpHeaders.AUTHORIZATION) final String authentication
    ) {
        logger.info("authentication: {}", authentication);
        return service.refreshToken(authentication);
    }

}
