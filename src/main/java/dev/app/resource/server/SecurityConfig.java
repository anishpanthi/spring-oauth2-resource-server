package dev.app.resource.server;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
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
import org.springframework.web.client.RestClient;

/**
 * @author Anish Panthi
 */
@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity
@Log4j2
public class SecurityConfig {

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
            });

    return http.csrf(AbstractHttpConfigurer::disable).build();
  }

  private final AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver =
      new CustomJwkSetUriResolver();

  static class CustomJwkSetUriResolver
      implements AuthenticationManagerResolver<HttpServletRequest> {

    @Override
    public AuthenticationManager resolve(HttpServletRequest request) {
      Map<String, String> jwkSetUriMap =
          Map.of(
              "OAuth",
              "https://dev-09980417.okta.com/oauth2/default",
              "nonOAuth",
              "https://apitest.hms.com/keys/v1");

      var authType = request.getHeader("auth-type");
      JwtDecoder jwtDecoder = new CustomJwtDecoder(jwkSetUriMap, authType);
      JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider(jwtDecoder);
      return new ProviderManager(authenticationProvider);
    }
  }

  static class CustomJwtDecoder implements JwtDecoder {

    private final Map<String, String> jwkSetUri;
    private final String authType;

    CustomJwtDecoder(Map<String, String> jwkSetUri, String authType) {
      this.jwkSetUri = jwkSetUri;
      this.authType = authType;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
      if (this.authType.equals("OAuth"))
        return JwtDecoders.fromIssuerLocation(jwkSetUri.get("OAuth")).decode(token);
      else {
        JWTClaimsSet claims;
        SignedJWT signedJWT;
        try {
          JWKSet jwkSet = JWKSet.load(new URI("https://apitest.hms.com/keys/v1").toURL());

          // TODO: Additional validation logic like signature can be added here

          signedJWT = SignedJWT.parse(token);
          claims = signedJWT.getJWTClaimsSet();
          log.info("Claims: {}", claims);
          if (claims.getExpirationTime().toInstant().isBefore(Instant.now()))
            throw new RuntimeException("Token has expired");

          // Get the roles of the user
          var userId = claims.getStringClaim("uid");
          var response =
              RestClient.builder()
                  .build()
                  .get()
                  .uri("https://apitest.hms.com/hmsuseraccesslist/?appl=tmv&env=test")
                  .header("Authorization", userId)
                  .retrieve()
                  .body(UserInfo.class);
          log.debug("Response: {}", response);
          assert response != null;
          String scope = "";
          for (var group : response.group()) {
            if (group.client().equals("console")) {
              scope = group.role().toUpperCase();
            }
          }

          Map<String, Object> claimsMap = new HashMap<>(claims.getClaims());
          claimsMap.put("scp", scope);

          return new Jwt(
              token,
              claims.getIssueTime().toInstant(),
              claims.getExpirationTime().toInstant(),
              signedJWT.getHeader().toJSONObject(),
              claimsMap);

        } catch (ParseException | IllegalArgumentException | NullPointerException e) {
          // TODO: Handle exception or log the error
          throw new RuntimeException(e);
        } catch (IOException | URISyntaxException e) {
          throw new RuntimeException(e);
        }
      }
    }
  }
}
