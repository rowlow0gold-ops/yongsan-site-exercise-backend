package com.example.demo.board.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class BoardPostWriteRequest {
    @NotBlank
    private String title;

    private String author;

    @NotBlank
    private String content;
}
