package com.programandoenjava.jwt.auth.controller;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.servlet.http.Cookie;

public record TokenResponse(
        @JsonProperty("access_token")
        String accessToken,
        @JsonProperty("refresh_token")
        String refreshToken,
        @JsonIgnore // Prevent sending the cookie in the response body
        Cookie jwtCookie
) {
}
