package dev.app.resource.server;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * @author Anish Panthi
 */
@RestController
public class ApiController {

  @GetMapping("/api/greet")
  public Map<String, String> greet() {
    return Map.of(
        "message", "Hello World! Welcome to Java Peer Group Session: Season 2, Episode 1");
  }
}
