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
public class ApiAuthenticationManagerResolver implements
    AuthenticationManagerResolver<HttpServletRequest> {

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
            "OAuth",
            "https://dev-09980417.okta.com/oauth2/default",
            "nonOAuth",
            "https://apitest.hms.com/keys/v1");

    var authType = context.getHeader("auth-type");
    JwtDecoder jwtDecoder = new ApiJwtDecoder(jwkSetUriMap, authType);
    JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider(jwtDecoder);
    return new ProviderManager(authenticationProvider);
  }
}
