package com.example.demo.config;

import io.sentry.Sentry;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class SentryExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleException(Exception e) {
        Sentry.captureException(e);
        return ResponseEntity.internalServerError()
                .body(new ErrorResponse("Internal server error"));
    }

    public record ErrorResponse(String message) {}
}
