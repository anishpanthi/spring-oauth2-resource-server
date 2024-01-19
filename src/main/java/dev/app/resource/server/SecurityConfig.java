package dev.app.resource.server;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author Anish Panthi
 */
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

  private final ApiAuthenticationConverter apiAuthenticationConverter;

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(
            request ->
                request.requestMatchers("/actuator/**").permitAll().anyRequest().authenticated())
        .oauth2ResourceServer(
            oauth -> {
              oauth.jwt(
                  jwtConfigurer ->
                      jwtConfigurer.jwtAuthenticationConverter(apiAuthenticationConverter));
            });

    return http.csrf(AbstractHttpConfigurer::disable).build();
  }
}
