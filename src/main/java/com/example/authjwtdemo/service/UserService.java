package com.example.authjwtdemo.service;

import com.example.authjwtdemo.data.Token;
import com.example.authjwtdemo.data.User;
import com.example.authjwtdemo.data.UserDao;
import com.example.authjwtdemo.error.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.relational.core.conversion.DbActionExecutionException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Objects;

@Service
public class UserService {

    private final UserDao userDao;
    private final PasswordEncoder passwordEncoder;
    private final String accessSecretKey;
    private final String refreshSecretKey;

    public UserService(UserDao userDao
            , PasswordEncoder passwordEncoder
            , @Value("${application.security.access-token-secret}") String accessSecretKey
            ,@Value("${application.security.refresh-token-secret}") String refreshSecretKey) {
        this.userDao = userDao;
        this.passwordEncoder = passwordEncoder;
        this.accessSecretKey = accessSecretKey;
        this.refreshSecretKey = refreshSecretKey;
    }

    public User register(String firstName, String lastName,
                         String email, String password, String confirmPassword) {
        if(!Objects.equals(password,confirmPassword)){
            throw new PasswordsDontMatchError();
        }

        User user=null;
        try{
            user=userDao.save(
                    User.of(firstName,
                            lastName,
                            email,
                            passwordEncoder.encode(password))
            );
        }catch (DbActionExecutionException e){
            throw new EmailAlreadyExistError();
        }
        return user;
    }

    public Login login(String email, String password) {
        var user=userDao.findUserByEmail(email)
                .orElseThrow(()-> new ResponseStatusException(HttpStatus.BAD_REQUEST,"invalid email!"));
        if(!passwordEncoder.matches(password,user.getPassword())){
            throw new InvalidCredentialsError();
        }
        var login=Login.of(user.getId(),accessSecretKey,refreshSecretKey);
        var refreshJwt= login.getRefreshToken();
        user.addToken(new Token(
                refreshJwt.getToken(),
                refreshJwt.getIssuedAt(),
                refreshJwt.getExpiredAt()
        ));
        userDao.save(user);
        return login;
    }

    public User getUserFromToken(String token) {
        return userDao.findById(Jwt.from(token,accessSecretKey).getUserId())
                .orElseThrow(UserNotFoundError::new);
    }

    public Login refreshAccess(String refreshToken) {
        var refreshJwt= Jwt.from(refreshToken,refreshSecretKey);
        var user=userDao
                .findByIdAndTokensRefreshToken(refreshJwt.getUserId(),
                        refreshJwt.getToken(),
                        refreshJwt.getExpiredAt())
                .orElseThrow(UnauthenticatedError::new);
        return Login.of(user.getId(),accessSecretKey, refreshToken);
    }

    public Boolean logout(String refreshToken){
        var refreshJwt= Jwt.from(refreshToken,refreshSecretKey);
        var user = userDao.findById(refreshJwt.getUserId())
                .orElseThrow(UnauthenticatedError::new);

        var  tokenIsRemoved = user
                .removeTokenIf(token -> Objects.equals(token.refreshToken(),refreshToken));
        if(tokenIsRemoved){
            userDao.save(user);
        }
        return tokenIsRemoved;
    }


}
