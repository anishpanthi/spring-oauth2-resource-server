package dev.app.resource.server;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.text.ParseException;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
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
@Log4j2
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
        try {
          JWKSet jwkSet = JWKSet.load(new URI("https://apitest.hms.com/keys/v1").toURL());
          SignedJWT signedJWT = SignedJWT.parse(token);

          // Extract the JWK from the JWK Set
          RSAKey rsaKey = (RSAKey) jwkSet.getKeyByKeyId(signedJWT.getHeader().getKeyID());

          // Build a JWS verifier from the JWK
          JWSVerifier verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());

          // Verify the signature
          if (!signedJWT.verify(verifier)) {
            // TODO: Invalid signature
          }

          // Additional validation logic can be added here
          JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
          log.info("Claims: {}", claims);
          // Validate claims, expiration, etc.
        } catch (ParseException
            | JOSEException
            | IllegalArgumentException
            | NullPointerException e) {
          // TODO: Handle exception or log the error
        } catch (IOException | URISyntaxException e) {
          throw new RuntimeException(e);
        }

        return JwtDecoders.fromIssuerLocation(jwkSetUri.get("nonOAuth")).decode(token);
      }
    }
  }
}
