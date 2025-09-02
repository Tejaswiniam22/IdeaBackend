package com.project.demo.security;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class LoginAttemptService {

    private final Map<String, FailedLogin> attemptsCache = new ConcurrentHashMap<>();
    private static final int MAX_ATTEMPTS = 5;
    private static final long BLOCK_TIME_MS = 10 * 60 * 1000; // 10 minutes

    public void loginFailed(String ip) {
        FailedLogin failedLogin = attemptsCache.getOrDefault(ip, new FailedLogin(0, Instant.now()));
        failedLogin.incrementAttempts();
        failedLogin.setLastAttempt(Instant.now());
        attemptsCache.put(ip, failedLogin);
    }

    public void loginSucceeded(String ip) {
        attemptsCache.remove(ip);
    }

    public boolean isBlocked(String ip) {
        FailedLogin failedLogin = attemptsCache.get(ip);
        if (failedLogin == null) {
            return false;
        }
        if (failedLogin.getAttempts() >= MAX_ATTEMPTS) {
            long elapsed = Instant.now().toEpochMilli() - failedLogin.getLastAttempt().toEpochMilli();
            if (elapsed < BLOCK_TIME_MS) {
                return true;
            } else {
                attemptsCache.remove(ip); // unblock after cooldown
            }
        }
        return false;
    }

    private static class FailedLogin {
        private int attempts;
        private Instant lastAttempt;

        public FailedLogin(int attempts, Instant lastAttempt) {
            this.attempts = attempts;
            this.lastAttempt = lastAttempt;
        }

        public int getAttempts() { return attempts; }
        public Instant getLastAttempt() { return lastAttempt; }
        public void setLastAttempt(Instant lastAttempt) { this.lastAttempt = lastAttempt; }
        public void incrementAttempts() { this.attempts++; }
    }
}
