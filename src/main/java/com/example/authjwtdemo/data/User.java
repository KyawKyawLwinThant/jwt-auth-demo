package com.example.authjwtdemo.data;

import lombok.Getter;
import lombok.ToString;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceConstructor;
import org.springframework.data.relational.core.mapping.MappedCollection;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Predicate;

@Getter
@ToString
public class User {

    @Id
    private Long id;
    private String firstName;
    private String lastName;
    private String email;
    private String password;

    @MappedCollection private final Set<Token> tokens=new HashSet<>();

    public static User of(String firstName,String lastName
            ,String email,String password){
        return new User(null,firstName,lastName,email,password,
                Collections.emptyList());
    }

    @PersistenceConstructor
    private User(Long id, String firstName, String lastName, String email
            , String password, Collection<Token> tokens) {
        this.id = id;
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        this.password = password;
        this.tokens.addAll(tokens);
    }

    public void addToken(Token token){
        this.tokens.add(token);
    }

    public Boolean removeToken(Token token){
        return this.tokens.remove(token);
    }
    public Boolean removeTokenIf(Predicate<? super Token> predicate){
        return this.tokens.removeIf(predicate);
    }











}
