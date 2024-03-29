package br.com.giulianabezerra.springsecurityjwt.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import br.com.giulianabezerra.springsecurityjwt.dtos.UserDTO;
import br.com.giulianabezerra.springsecurityjwt.security.AuthenticationService;

@RestController
public class AuthenticationController {
  @Autowired
  private AuthenticationService authenticationService;

  @PostMapping("authenticate")
  public String authenticate(
      Authentication authentication) {
    return authenticationService.authenticate(authentication);
  }
  
  @PostMapping("register")
  public String insert(@RequestBody UserDTO userDto) {
	  return authenticationService.insert(userDto);  
  }
}
