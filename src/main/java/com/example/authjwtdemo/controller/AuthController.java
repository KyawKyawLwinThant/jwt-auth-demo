package com.example.authjwtdemo.controller;

import com.example.authjwtdemo.data.User;
import com.example.authjwtdemo.data.UserDao;
import com.example.authjwtdemo.service.UserService;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Objects;

@RestController
@RequestMapping("/api")
public class AuthController {


    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    record RegisterRequest(@JsonProperty("first_name")String firstName,
                           @JsonProperty("last_name")String lastName,
                           String email,String password,
                          @JsonProperty("confirm_password")String confirmPassword){}

    record RegisterResponse(Long id,@JsonProperty("first_name")String firstName,
                            @JsonProperty("last_name")String lastName,
                            String email){}
    //curl -X POST -H "Content-Type: application/json" -d
    // '{"first_name":"Angle","last_name":"Chan","email":"angle@gmail.com","password":"12345","confirm_password":"12345"}'
    @PostMapping("/register")
    public RegisterResponse register(@RequestBody RegisterRequest registerRequest){

        User user= userService.register(
                        registerRequest.firstName(),
                        registerRequest.lastName(),
                        registerRequest.email(),
                        registerRequest.password(),
                        registerRequest.confirmPassword()
        );
        return new RegisterResponse(
                user.getId(),
                user.getFirstName(),
                user.getLastName(),
                user.getEmail()
        );
    }
    record LoginRequest(String email,String password){}
    record LoginResponse(String token){}
    //curl -X POST -H "Content-Type: application/json" -d '{"email":"angle@gmail.com","password":"12345"}' localhost:8000/api/login
    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest loginRequest,
                               HttpServletResponse response){
        var login=userService.login(loginRequest.email(),loginRequest.password());
        Cookie cookie=new Cookie("refresh_token",login.getRefreshToken().getToken());
        cookie.setMaxAge(3600);
        cookie.setHttpOnly(true);
        cookie.setPath("/api");
        response.addCookie(cookie);
        return new LoginResponse(
                login.getAccessToken().getToken()
        );
    }
    record UserResponse(Long id,@JsonProperty("first_name")String firstName,
                            @JsonProperty("last_name")String lastName,
                            String email){}
    @GetMapping("/user")
    public UserResponse user(HttpServletRequest request){
        var user=(User) request.getAttribute("user");
        return new UserResponse(user.getId(),user.getFirstName(),user.getLastName(),
                user.getEmail());
    }
    record RefreshResponse(String token){}
    @PostMapping("/refresh")
    public RefreshResponse refresh(@CookieValue("refresh_token")String refreshToken){
            return new RefreshResponse(userService.refreshAccess(refreshToken)
                    .getAccessToken()
                    .getToken());
    }
    record LogoutResponse(String msg){}
    @PostMapping("/logout")
    public LogoutResponse logout(@CookieValue("refresh_token")String refreshToken,
                                 HttpServletResponse response){
        userService.logout(refreshToken);
        Cookie cookie=new Cookie("refresh_token",null);
        cookie.setMaxAge(0);
        cookie.setHttpOnly(true);
        response.addCookie(cookie);

        return new LogoutResponse("successful logout!");
    }

    record ForgotRequest(String email){}
    record ForgotResponse(String message){}

    @PostMapping("/forgot")
    public ForgotResponse forgot(@RequestBody ForgotRequest forgotRequest,
                                 HttpServletRequest request
    ){
        var orginUrl = request.getHeader("Origin");
        userService.forget(forgotRequest.email,orginUrl);
        return new ForgotResponse("success");
    }
    record ResetRequest(String token,String password,
                        @JsonProperty("password_confirm")String passwordConfirm){}
    record ResetResponse(String message){}
    @PostMapping("/reset")
    public ResetResponse reset(@RequestBody ResetRequest resetRequest){
        userService.reset(resetRequest.token(),
                resetRequest.password(),
                resetRequest.passwordConfirm());
        return new ResetResponse("success reset password");
    }










}
