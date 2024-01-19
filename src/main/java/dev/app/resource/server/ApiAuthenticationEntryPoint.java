package dev.app.resource.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * @author Anish Panthi
 */
@Log4j2
@Component
@RequiredArgsConstructor
public class ApiAuthenticationEntryPoint implements AuthenticationEntryPoint, Serializable {

  private final ObjectMapper objectMapper;
  @Setter private String realmName;

  private static String computeWWWAuthenticateHeaderValue(Map<String, String> parameters) {
    var wwwAuthenticate = new StringBuilder();
    wwwAuthenticate.append("Bearer");
    if (!parameters.isEmpty()) {
      wwwAuthenticate.append(" ");
      int i = 0;

      for (var var3 = parameters.entrySet().iterator(); var3.hasNext(); ++i) {
        Map.Entry<String, String> entry = var3.next();
        wwwAuthenticate.append(entry.getKey()).append("=\"").append(entry.getValue()).append("\"");
        if (i != parameters.size() - 1) {
          wwwAuthenticate.append(", ");
        }
      }
    }
    return wwwAuthenticate.toString();
  }

  /**
   * @param request - HttpServletRequest
   * @param response - HttpServletResponse
   * @param authException - AuthenticationException
   * @throws IOException - IOException
   * @throws ServletException - ServletException
   */
  @Override
  public void commence(
      HttpServletRequest request,
      HttpServletResponse response,
      AuthenticationException authException)
      throws IOException, ServletException {

    HttpStatus status = HttpStatus.UNAUTHORIZED;
    Map<String, String> parameters = new LinkedHashMap<>();
    if (this.realmName != null) {
      parameters.put("realm", this.realmName);
    }

    if (authException instanceof OAuth2AuthenticationException) {
      OAuth2Error error = ((OAuth2AuthenticationException) authException).getError();
      parameters.put("error", error.getErrorCode());
      if (StringUtils.hasText(error.getDescription())) {
        parameters.put("error_description", error.getDescription());
      }

      if (StringUtils.hasText(error.getUri())) {
        parameters.put("error_uri", error.getUri());
      }

      if (error instanceof BearerTokenError bearerTokenError) {
        if (StringUtils.hasText(bearerTokenError.getScope())) {
          parameters.put("scope", bearerTokenError.getScope());
        }

        status = ((BearerTokenError) error).getHttpStatus();
      }
    }

    String wwwAuthenticate = computeWWWAuthenticateHeaderValue(parameters);
    response.addHeader("WWW-Authenticate", wwwAuthenticate);
    response.setStatus(status.value());
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);

    var authErrorResponse =
        new ApiErrorResponse(
            LocalDateTime.now().toString(), "APP401", "UNAUTHORIZED", authException.getMessage());
    response.getWriter().write(objectMapper.writeValueAsString(authErrorResponse));
  }
}
