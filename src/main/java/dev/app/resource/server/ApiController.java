package dev.app.resource.server;

import java.util.Map;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Anish Panthi
 */
@RestController
@Log4j2
public class ApiController {

  @GetMapping("/api/greet")
  public Map<String, String> greet() {
    return Map.of(
        "message", "Hello World! Welcome to Spring's OAuth2.0 & OpenID Connect demo!");
  }

  @GetMapping
  public Map<String, Object> secure(@AuthenticationPrincipal OidcUser oidcUser) {
    log.info("User details: {}", oidcUser);
    return Map.of(
        "message",
        "Hello World! Welcome to Spring's OAuth2.0 & OpenID Connect demo",
        "claims",
        oidcUser.getClaims());
  }
}
