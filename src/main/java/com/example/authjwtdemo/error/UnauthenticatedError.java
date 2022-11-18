package com.example.authjwtdemo.error;


import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class UnauthenticatedError extends ResponseStatusException {

    public UnauthenticatedError(){
        super(HttpStatus.UNAUTHORIZED,"Authentication Error");
    }
}
