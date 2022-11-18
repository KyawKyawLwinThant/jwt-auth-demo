package com.example.authjwtdemo.intercepter;

import com.example.authjwtdemo.error.NoBearerToken;
import com.example.authjwtdemo.service.UserService;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class AuthorizationInterceptor implements HandlerInterceptor {
    private final UserService userService;

    public AuthorizationInterceptor(UserService userService) {
        this.userService = userService;
    }
    //Bearer token

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String authorizationHandler = request.getHeader("Authorization");

        if(authorizationHandler == null ||
                !authorizationHandler.startsWith("Bearer ")){
            throw new NoBearerToken();
        }
        request.setAttribute("user",userService
                .getUserFromToken(authorizationHandler.substring(7)));
        return true;
    }
}
