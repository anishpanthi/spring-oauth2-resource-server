package dev.app.resource.server;

import java.util.Map;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Anish Panthi
 */
@RestController
@RequestMapping("/api")
public class ApiController {

  @PreAuthorize("hasAnyAuthority('SCOPE_READ_ME','SCOPE_my_data','SCOPE_ADMIN')")
  @GetMapping("/greet")
  public Map<String, String> greet() {
    return Map.of(
        "message", "Hello World! Welcome to Java Peer Group Session: Season 2, Episode 2");
  }
}
