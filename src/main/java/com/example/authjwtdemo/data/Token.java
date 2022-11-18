package com.example.authjwtdemo.data;

import java.time.LocalDate;
import java.time.LocalDateTime;

public record Token(String refreshToken,
                    LocalDateTime issuedAt,
                    LocalDateTime expiredAt) {
}
