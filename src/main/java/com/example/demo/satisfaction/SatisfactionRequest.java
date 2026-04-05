package com.example.demo.satisfaction;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;

@Getter
public class SatisfactionRequest {

    @NotBlank
    @Size(max = 500)
    private String pagePath;

    @NotBlank
    @Pattern(regexp = "매우 만족|만족|보통|불만|매우 불만", message = "Invalid rating")
    private String rating;

    @Size(max = 200)
    private String feedback;
}
