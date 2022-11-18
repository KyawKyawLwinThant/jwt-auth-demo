package com.example.authjwtdemo.error;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class UserNotFoundError extends ResponseStatusException {

    public UserNotFoundError(){
        super(HttpStatus.NOT_FOUND,"User is not found!");
    }
}
