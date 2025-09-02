package com.project.demo.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.project.demo.model.RefreshToken;
import com.project.demo.model.User;
import com.project.demo.security.JwtUtil;
import com.project.demo.service.RefreshTokenService;
import com.project.demo.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;

    public AuthController(UserService userService, JwtUtil jwtUtil,
                          AuthenticationManager authenticationManager,
                          RefreshTokenService refreshTokenService) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        try {
            log.info("Register attempt for user: {}", user.getUsername());
            String message = userService.register(user);
            log.info("User registered successfully: {}", user.getUsername());
            return ResponseEntity.ok(Map.of("message", message));
        } catch (IllegalStateException e) {
            log.warn("Registration failed for user {}: {}", user.getUsername(), e.getMessage());
            return ResponseEntity.status(400).body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> req,
                                   HttpServletRequest request,
                                   HttpServletResponse response) {
        String username = req.get("username");
        try {
            log.info("Login attempt for user: {}", username);

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, req.get("password"))
            );

            String accessToken = jwtUtil.generateToken(authentication.getName());
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(authentication.getName());

            Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken.getToken());
            refreshTokenCookie.setHttpOnly(true);
            refreshTokenCookie.setSecure(false);
            refreshTokenCookie.setPath("/");
            refreshTokenCookie.setMaxAge(604800);
            response.addCookie(refreshTokenCookie);

            // Collect login details
            Map<String, Object> logEntry = createLoginLog(username, request);

            // Save to JSON file
            saveLoginLog(logEntry);

            log.info("Login successful for user: {} | IP: {} | Browser: {} | Device: {}",
                    username, logEntry.get("ip"), logEntry.get("browser"), logEntry.get("device"));

            return ResponseEntity.ok(Map.of("accessToken", accessToken, "refreshToken", refreshToken.getToken()));
        } catch (BadCredentialsException e) {
            log.warn("Login failed for user {}: Invalid credentials", username);
            return ResponseEntity.status(401).body(Map.of("error", "Invalid username or password"));
        } catch (Exception e) {
            log.error("Unexpected error during login for user {}: {}", username, e.getMessage(), e);
            return ResponseEntity.status(500).body(Map.of("error", "Internal server error"));
        }
    }

    private Map<String, Object> createLoginLog(String username, HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        String browser = request.getHeader("X-Browser");
        String os = request.getHeader("X-OS");
        String device = request.getHeader("X-Device");

        Map<String, Object> logEntry = new LinkedHashMap<>();
        logEntry.put("username", username);
        logEntry.put("ip", ipAddress);
        logEntry.put("browser", browser != null ? browser : userAgent);
        logEntry.put("os", os);
        logEntry.put("device", device);
        logEntry.put("timestamp", new Date().toString());
        return logEntry;
    }

    private void saveLoginLog(Map<String, Object> logEntry) {
        try {
            File file = new File("data/user.json");
            ObjectMapper mapper = new ObjectMapper();
            List<Map<String, Object>> logs;

            if (file.exists() && file.length() > 0L) {
                logs = mapper.readValue(file, new TypeReference<>() {});
            } else {
                logs = new ArrayList<>();
            }

            logs.add(logEntry);
            mapper.writerWithDefaultPrettyPrinter().writeValue(file, logs);
            log.info("Login log saved to JSON for user: {}", logEntry.get("username"));
        } catch (Exception e) {
            log.error("Failed to save login log to JSON: {}", e.getMessage(), e);
        }
    }

    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        Optional<String> refreshTokenOpt = Optional.ofNullable(request.getCookies())
                .flatMap(cookies -> Arrays.stream(cookies)
                        .filter(c -> "refreshToken".equals(c.getName()))
                        .map(Cookie::getValue)
                        .findFirst());

        if (refreshTokenOpt.isEmpty()) {
            log.warn("Refresh token not found in cookies");
            return ResponseEntity.status(401).body(Map.of("error", "Refresh token not found in cookie"));
        }

        String oldToken = refreshTokenOpt.get();

        return refreshTokenService.findByToken(oldToken)
                .map(refreshTokenService::verifyExpiration)
                .map(rt -> {
                    String username = rt.getUsername();
                    refreshTokenService.deleteByToken(oldToken);

                    String newAccessToken = jwtUtil.generateToken(username);
                    RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(username);

                    Cookie newRefreshTokenCookie = new Cookie("refreshToken", newRefreshToken.getToken());
                    newRefreshTokenCookie.setHttpOnly(true);
                    newRefreshTokenCookie.setSecure(false);
                    newRefreshTokenCookie.setPath("/");
                    newRefreshTokenCookie.setMaxAge(7 * 24 * 60 * 60);
                    response.addCookie(newRefreshTokenCookie);

                    log.info("Refresh token rotated successfully for user: {}", username);
                    return ResponseEntity.ok(Map.of(
                            "accessToken", newAccessToken,
                            "refreshToken", newRefreshToken.getToken()
                    ));
                })
                .orElseGet(() -> {
                    log.warn("Invalid refresh token provided");
                    return ResponseEntity.status(401).body(Map.of("error", "Invalid refresh token"));
                });
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        Optional<String> refreshTokenOpt = Optional.ofNullable(request.getCookies())
                .flatMap(cookies -> Arrays.stream(cookies)
                        .filter(c -> "refreshToken".equals(c.getName()))
                        .map(Cookie::getValue)
                        .findFirst());

        refreshTokenOpt.ifPresent(token -> {
            refreshTokenService.deleteByToken(token);
            log.info("Refresh token invalidated on logout");
        });

        Cookie clearedCookie = new Cookie("refreshToken", null);
        clearedCookie.setMaxAge(0);
        clearedCookie.setPath("/");
        response.addCookie(clearedCookie);

        log.info("User successfully logged out");
        return ResponseEntity.ok(Map.of("message", "Successfully logged out"));
    }
}
