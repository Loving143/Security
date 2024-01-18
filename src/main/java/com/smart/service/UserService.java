package com.smart.service;



import org.springframework.security.core.userdetails.UserDetailsService;

//import org.springframework.security.core.userdetails.UserDetailsService;

import com.smart.dto.UserRegistrationDto;
import com.smart.model.User;

public interface UserService  extends UserDetailsService{
	User save(UserRegistrationDto registrationDto);
} 

