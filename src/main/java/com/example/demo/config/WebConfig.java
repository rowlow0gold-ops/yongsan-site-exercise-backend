package com.example.demo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * CORS for this app lives in SecurityConfig (the Spring Security CorsFilter
 * runs before the MVC CORS handler and would override anything set here
 * anyway). Keeping this file as a placeholder for future MVC-level config.
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {
}
