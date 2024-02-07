package dev.app.resource.server;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.stereotype.Component;

/**
 * @author Anish Panthi
 */
@Component
@Log4j2
public class ApiAuthenticationManagerResolver
    implements AuthenticationManagerResolver<HttpServletRequest> {

  /**
   * Resolve an {@link AuthenticationManager} from a provided context
   *
   * @param context the context to resolve
   * @return the {@link AuthenticationManager} to use
   */
  @Override
  public AuthenticationManager resolve(HttpServletRequest context) {
    Map<String, String> jwkSetUriMap =
        Map.of(
            "okta",
            "https://dev-09980417.okta.com/oauth2/default",
            "b2c",
            "https://anishpanthi41gmail.b2clogin.com/tfp/1b286c40-c2fd-46d5-a553-b6502b89f42d/b2x_1_anish/v2.0/",
            "l7",
            "https://apitest.hms.com/keys/v1");

    var issuer = context.getHeader("issuer");
    JwtDecoder jwtDecoder = new ApiJwtDecoder(jwkSetUriMap, issuer);
    JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider(jwtDecoder);
    return new ProviderManager(authenticationProvider);
  }
}
