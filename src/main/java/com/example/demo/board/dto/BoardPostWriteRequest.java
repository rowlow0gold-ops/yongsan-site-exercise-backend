package com.example.demo.board.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;

@Getter
public class BoardPostWriteRequest {

    @NotBlank
    private String title;

    private String author;

    @NotBlank
    private String content;

    // for praise board (guest)
    @Size(min = 6, message = "Password must be at least 6 characters.")
    private String password;
}