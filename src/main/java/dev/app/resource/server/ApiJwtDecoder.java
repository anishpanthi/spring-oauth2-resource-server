package dev.app.resource.server;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.client.RestClient;

/**
 * @author Anish Panthi
 */
@Log4j2
public class ApiJwtDecoder implements JwtDecoder {

  private final Map<String, String> jwkSetUri;
  private final String authType;

  ApiJwtDecoder(Map<String, String> jwkSetUri, String authType) {
    this.jwkSetUri = jwkSetUri;
    this.authType = authType;
  }

  /**
   * @param token String
   * @return Jwt
   * @throws JwtException Exception to be thrown
   */
  @Override
  public Jwt decode(String token) throws JwtException {
    if (this.authType.equals("OAuth")) {
      return JwtDecoders.fromIssuerLocation(jwkSetUri.get("OAuth")).decode(token);
    } else {
      JWTClaimsSet claims;
      SignedJWT signedJWT;
      try {
//        TODO: JWKSet jwkSet = JWKSet.load(new URI("https://apitest.hms.com/keys/v1").toURL());
//        TODO: Validate signature before parsing the token

        signedJWT = SignedJWT.parse(token);
        claims = signedJWT.getJWTClaimsSet();
        log.info("Claims: {}", claims);
        if (claims.getExpirationTime().toInstant().isBefore(Instant.now())) {
          throw new RuntimeException("Token has expired");
        }

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

        AtomicReference<String> scope = new AtomicReference<>("");
        response.group().stream()
            .filter(group -> group.client().equals("console"))
            .findFirst()
            .ifPresent(group -> scope.set(group.role().toUpperCase()));

        Map<String, Object> claimsMap = new HashMap<>(claims.getClaims());
        claimsMap.put("scp", scope);

        return new Jwt(
            token,
            claims.getIssueTime().toInstant(),
            claims.getExpirationTime().toInstant(),
            signedJWT.getHeader().toJSONObject(),
            claimsMap);

      } catch (ParseException
               | IllegalArgumentException
               | NullPointerException e) {
        throw new RuntimeException(e);
      }
    }
  }
}
