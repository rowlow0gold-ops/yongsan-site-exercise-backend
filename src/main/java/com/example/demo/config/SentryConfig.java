package com.example.demo.config;

import io.sentry.Sentry;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SentryConfig {

    @Value("${sentry.dsn:}")
    private String dsn;

    @Value("${sentry.environment:local}")
    private String environment;

    @Value("${sentry.traces-sample-rate:1.0}")
    private double tracesSampleRate;

    @PostConstruct
    public void init() {
        if (dsn != null && !dsn.isBlank()) {
            Sentry.init(options -> {
                options.setDsn(dsn);
                options.setEnvironment(environment);
                options.setTracesSampleRate(tracesSampleRate);
            });
        }
    }
}
