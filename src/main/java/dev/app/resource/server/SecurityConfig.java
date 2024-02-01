package dev.app.resource.server;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author Anish Panthi
 */
@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfig {

  private final ApiAuthenticationConverter apiAuthenticationConverter;

  private final ApiAuthenticationEntryPoint apiAuthenticationEntryPoint;

  private final ApiAccessDeniedHandler jwtAccessDeniedHandler;

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

//    JwtIssuerAuthenticationManagerResolver authenticationManagerResolver =
//        JwtIssuerAuthenticationManagerResolver.fromTrustedIssuers(
//            "https://dev-09980417.okta.com/oauth2/default");

    http.authorizeHttpRequests(
            request ->
                request.requestMatchers("/actuator/**").permitAll().anyRequest().authenticated())
        .oauth2ResourceServer(
            oauth -> {
              oauth.authenticationManagerResolver(authenticationManagerResolver);
//              oauth.jwt(
//                  jwtConfigurer ->
//                      jwtConfigurer.jwtAuthenticationConverter(apiAuthenticationConverter));
              oauth.authenticationEntryPoint(apiAuthenticationEntryPoint);
              oauth.accessDeniedHandler(jwtAccessDeniedHandler);
            });

    return http.csrf(AbstractHttpConfigurer::disable).build();
  }

  private final AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver = new CustomJwkSetUriResolver();

  static class CustomJwkSetUriResolver implements
      AuthenticationManagerResolver<HttpServletRequest> {

    @Override
    public AuthenticationManager resolve(HttpServletRequest request) {
      var JWK_SET_URI_1 = "https://dev-09980417.okta.com/oauth2/default";
      var JWK_SET_URI_2 = "https://apitest.hms.com/keys/v1";

      JwtDecoder jwtDecoder = new CustomJwtDecoder(JWK_SET_URI_1);
      JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider(jwtDecoder);
      return new ProviderManager(authenticationProvider);
    }
  }

  static class CustomJwtDecoder implements JwtDecoder {

    private final String jwkSetUri;

    CustomJwtDecoder(String jwkSetUri) {
      this.jwkSetUri = jwkSetUri;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
      // TODO: Perform manual validation using the jwk-set-uri or other logic
      return JwtDecoders.fromIssuerLocation(jwkSetUri).decode(token);
    }
  }
}
