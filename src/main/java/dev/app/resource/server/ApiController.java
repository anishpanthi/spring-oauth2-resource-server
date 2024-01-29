package dev.app.resource.server;

import java.util.Map;
import lombok.extern.log4j.Log4j2;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
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
        "message", "Hello World! Welcome to Java Peer Group Session: Season 2, Episode 1");
  }

  @GetMapping("/api/secure")
  public Map<String, String> secure(@PathVariable String token) {
    log.info("Token: {}", token);
    return Map.of(
        "message", "Hello World! Welcome to Java Peer Group Session: Season 2, Episode 1");
  }
}
