package br.com.giulianabezerra.springsecurityjwt.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("private")
public class PrivateController {

  @GetMapping
  //@PreAuthorize("hasAuthority('ROLE_ADMIN')")
  public String getMessage() {
    return "Hello from private API controller";
  }
  
}
