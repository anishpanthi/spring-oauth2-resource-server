package dev.app.resource.server;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author Anish Panthi
 */
@Configuration
public class SecurityConfig {

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(
            request ->
                request.requestMatchers("/actuator/**").permitAll().anyRequest().authenticated())
        .csrf(AbstractHttpConfigurer::disable);
    return http.build();
  }
}