package br.com.giulianabezerra.springsecurityjwt.security;

import java.util.Optional;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import br.com.giulianabezerra.springsecurityjwt.model.User;
import br.com.giulianabezerra.springsecurityjwt.repository.UserRepository;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
  private final UserRepository userRepository;

  public UserDetailsServiceImpl(UserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
	Optional<User> userOptional = userRepository.findByUsername(username);
	
	User user = userOptional.orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));
	
    return new UserAuthenticated(user.getUsername(), user.getPassword());
  }

}
