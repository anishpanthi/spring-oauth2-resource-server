package dev.app.resource.server;

import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * @author Anish Panthi
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(
            authorizeRequests ->
                authorizeRequests
                    .requestMatchers("/oauth2/**")
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .oauth2Login(oauth2 -> oauth2.tokenEndpoint(tokenEndpoint -> tokenEndpoint.accessTokenResponseClient(this::getTokenResponse)));
    return http.build();
  }

  private OAuth2AccessTokenResponse getTokenResponse(
      OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) {
    DefaultAuthorizationCodeTokenResponseClient client =
        new DefaultAuthorizationCodeTokenResponseClient();
    client.setRestOperations(restOperations());
    return client.getTokenResponse(authorizationGrantRequest);
  }

  private RestOperations restOperations() {
    OAuth2AccessTokenResponseHttpMessageConverter converter =
        new OAuth2AccessTokenResponseHttpMessageConverter();
    converter.setAccessTokenResponseConverter(getConverter());
    RestTemplate restTemplate =
        new RestTemplate(Arrays.asList(new FormHttpMessageConverter(), converter));
    restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
    return restTemplate;
  }

  private Converter<Map<String, Object>, OAuth2AccessTokenResponse> getConverter() {
    return map ->
        OAuth2AccessTokenResponse.withToken((String) map.get("id_token"))
            .tokenType(OAuth2AccessToken.TokenType.BEARER)
            .scopes(Set.of(map.get("scope").toString()))
            .expiresIn(Long.parseLong(String.valueOf(map.get("not_before"))))
            .additionalParameters(Map.of("id_token", map.get("id_token")))
            .build();
  }
}
