package com.example.demo.config;

import io.sentry.Sentry;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SentryConfig {

    private static final Logger log = LoggerFactory.getLogger(SentryConfig.class);

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
                options.setDebug(true);
            });
            log.info("✅ Sentry initialized with DSN: {}...{}", dsn.substring(0, 20), dsn.substring(dsn.length() - 10));
        } else {
            log.warn("⚠️ Sentry DSN is empty — Sentry is NOT active");
        }
    }
}
