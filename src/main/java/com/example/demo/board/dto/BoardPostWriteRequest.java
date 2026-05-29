package com.example.demo.board.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;

@Getter
public class BoardPostWriteRequest {

    @NotBlank @Size(max = 200)
    private String title;

    @Size(max = 100)
    private String author;

    @NotBlank @Size(max = 20000)
    private String content;

    // for praise board (guest)
    @Size(min = 6, max = 100, message = "Password must be at least 6 characters.")
    private String password;

    @Pattern(regexp = "PUBLIC|PRIVATE", message = "visibility must be PUBLIC or PRIVATE")
    private String visibility = "PUBLIC";

    /** Cloudflare Turnstile widget token. Required on create. */
    @NotBlank
    private String cfTurnstileToken;
}
