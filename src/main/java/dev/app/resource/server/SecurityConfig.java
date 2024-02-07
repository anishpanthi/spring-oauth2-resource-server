package dev.app.resource.server;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author Anish Panthi
 */
@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity
@Log4j2
public class SecurityConfig {

  private final ApiAuthenticationManagerResolver authenticationManagerResolver;

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    //    JwtIssuerAuthenticationManagerResolver authenticationManagerResolver =
    //        JwtIssuerAuthenticationManagerResolver.fromTrustedIssuers(
    //            "https://dev-09980417.okta.com/oauth2/default",
    //
    // "https://anishpanthi41gmail.b2clogin.com/tfp/1b286c40-c2fd-46d5-a553-b6502b89f42d/b2x_1_anish/v2.0/");

    http.authorizeHttpRequests(
            request ->
                request.requestMatchers("/actuator/**").permitAll().anyRequest().authenticated())
        .oauth2ResourceServer(
            oauth -> oauth.authenticationManagerResolver(authenticationManagerResolver));
    return http.csrf(AbstractHttpConfigurer::disable).build();
  }
}
