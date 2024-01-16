package br.com.giulianabezerra.springsecurityjwt.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import br.com.giulianabezerra.springsecurityjwt.model.User;
import br.com.giulianabezerra.springsecurityjwt.repository.UserRepository;
import br.com.giulianabezerra.springsecurityjwt.dtos.UserDTO;

@Service
public class AuthenticationService {
	
  private JwtService jwtService;
  
  private PasswordEncoder passwordEncoder;
  
  private UserRepository userRepository;

  public AuthenticationService(JwtService jwtService, PasswordEncoder passwordEncoder, UserRepository userRepository) {
    this.jwtService = jwtService;
    this.passwordEncoder = passwordEncoder;
    this.userRepository = userRepository;
  }

  public String authenticate(Authentication authentication) {
    return jwtService.generateToken(authentication);
  }
  
  public String insert(UserDTO userDto) {
	  User user = new User();
	  user.setUsername(userDto.getUsername());
	  user.setPassword(passwordEncoder.encode(userDto.getPassword()));
	  	  
	  userRepository.save(user);
	  
	  return "Cadastro efetuado com sucesso";
  }
}
