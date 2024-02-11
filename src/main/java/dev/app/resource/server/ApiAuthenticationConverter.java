package dev.app.resource.server;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * @author Anish Panthi
 */
@Component
@Log4j2
@RequiredArgsConstructor
public class ApiAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

  private final RestClient restClient;

  private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter =
      new JwtGrantedAuthoritiesConverter();

  @Override
  public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {
    log.info("JwtAuthenticationConverter - JWT Token: {}", jwt.getClaims().toString());
    var authorities =
        Stream.concat(
                jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
                Objects.requireNonNull(extractRoles(jwt)).stream())
            .collect(Collectors.toSet());
    return new JwtAuthenticationToken(jwt, authorities, jwt.getClaim("uid"));
  }

  /**
   * The below method is the implementation for my use case. I've a 2 different endpoints, which
   * takes care of AuthN and AuthZ. The AuthZ endpoint returns the roles for the user. The below
   * method is used to extract the roles from the JWT token and then call the AuthZ endpoint to get
   * the roles for the user.
   * <p>
   * Not everyone will have this use case, so you can ignore this method and use the default
   * implementation.
   *
   * @param jwt the JWT token
   * @return the roles
   */
  private Collection<GrantedAuthority> extractRoles(Jwt jwt) {
    var userId = jwt.getClaimAsString("uid");
    if (userId == null) {
      return Set.of();
    }

    var response =
        restClient
            .get()
            .uri("<replace-with-your-user-access-list-api-url>")
            .header("Authorization", userId)
            .retrieve()
            .body(UserInfo.class);
    log.debug("Response: {}", response);
    assert response != null;
    if (response.group() == null) {
      return Set.of();
    }
    var authorityList = new ArrayList<GrantedAuthority>();
    var userHasAccessTo = new HashSet<String>();
    for (var group : response.group()) {
      userHasAccessTo.add(group.client() + ":ROLE_" + group.role().toUpperCase());
      if (group.client().equals("console")) {
        authorityList.add(new SimpleGrantedAuthority("ROLE_" + group.role().toUpperCase()));
      }
    }
    log.debug("User has access to: {}", String.join(",", userHasAccessTo));
    return !authorityList.isEmpty() ? authorityList : Set.of();
  }
}
