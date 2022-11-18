package com.example.authjwtdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jdbc.repository.config.EnableJdbcRepositories;

@SpringBootApplication
@EnableJdbcRepositories
public class AuthJwtDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthJwtDemoApplication.class, args);
    }

}
