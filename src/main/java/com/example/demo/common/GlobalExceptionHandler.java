package com.example.demo.common;

import io.sentry.Sentry;
import io.sentry.protocol.SentryId;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.time.Instant;
import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<ApiError> notFound(EntityNotFoundException e, HttpServletRequest req) {
        // 404 — don't send to Sentry
        return ResponseEntity.status(404).body(ApiError.of(404, "NOT_FOUND", e.getMessage(), req.getRequestURI()));
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ApiError> noResource(NoResourceFoundException e, HttpServletRequest req) {
        // 404 — don't send to Sentry
        return ResponseEntity.status(404).body(ApiError.of(404, "NOT_FOUND", "Not found", req.getRequestURI()));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiError> forbidden(AccessDeniedException e, HttpServletRequest req) {
        return ResponseEntity.status(403).body(ApiError.of(403, "FORBIDDEN", e.getMessage(), req.getRequestURI()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiError> badRequest(IllegalArgumentException e, HttpServletRequest req) {
        return ResponseEntity.status(400).body(ApiError.of(400, "BAD_REQUEST", e.getMessage(), req.getRequestURI()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> validation(MethodArgumentNotValidException e, HttpServletRequest req) {
        String msg = e.getBindingResult().getAllErrors().stream()
                .map(err -> {
                    if (err instanceof FieldError fe) return fe.getField() + ": " + fe.getDefaultMessage();
                    return err.getDefaultMessage();
                })
                .collect(Collectors.joining(", "));

        return ResponseEntity.status(400).body(ApiError.of(400, "VALIDATION_ERROR", msg, req.getRequestURI()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> server(Exception e, HttpServletRequest req) {
        // Send to Sentry
        log.error("🚨 Sentry capturing exception: {}", e.getMessage());
        SentryId id = Sentry.captureException(e);
        log.error("🚨 Sentry event ID: {}", id);
        Sentry.flush(5000);
        log.error("🚨 Sentry flush done");

        return ResponseEntity.status(500).body(ApiError.of(500, "INTERNAL_ERROR", "Internal Server Error", req.getRequestURI()));
    }

    public record ApiError(Instant timestamp, int status, String error, String message, String path) {
        public static ApiError of(int status, String error, String message, String path) {
            return new ApiError(Instant.now(), status, error, message, path);
        }
    }

    @ExceptionHandler(org.springframework.web.method.annotation.MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ApiError> typeMismatch(Exception e, HttpServletRequest req) {
        return ResponseEntity.status(400)
                .body(ApiError.of(400, "BAD_REQUEST", "Invalid parameter", req.getRequestURI()));
    }
}