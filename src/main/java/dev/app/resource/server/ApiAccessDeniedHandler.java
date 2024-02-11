package dev.app.resource.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

@Component
@Log4j2
@RequiredArgsConstructor
public class ApiAccessDeniedHandler implements AccessDeniedHandler {

  private final ObjectMapper objectMapper;
  @Setter
  private String realmName;

  private static String computeWWWAuthenticateHeaderValue(Map<String, String> parameters) {
    var wwwAuthenticate = new StringBuilder();
    wwwAuthenticate.append("Bearer");
    if (!parameters.isEmpty()) {
      wwwAuthenticate.append(" ");
      int i = 0;

      for (var var3 = parameters.entrySet().iterator(); var3.hasNext(); ++i) {
        var entry = var3.next();
        wwwAuthenticate.append(entry.getKey()).append("=\"").append(entry.getValue()).append("\"");
        if (i != parameters.size() - 1) {
          wwwAuthenticate.append(", ");
        }
      }
    }

    return wwwAuthenticate.toString();
  }

  @Override
  public void handle(
      HttpServletRequest request,
      HttpServletResponse response,
      AccessDeniedException accessDeniedException)
      throws IOException, ServletException {

    var parameters = new LinkedHashMap<String, String>();
    if (this.realmName != null) {
      parameters.put("realm", this.realmName);
    }

    if (request.getUserPrincipal() instanceof AbstractOAuth2TokenAuthenticationToken) {
      parameters.put("error", "insufficient_scope");
      parameters.put(
          "error_description",
          "The request requires higher privileges than provided by the access token.");
      parameters.put("error_uri", "https://tools.ietf.org/html/rfc6750#section-3.1");
    }

    var wwwAuthenticate = computeWWWAuthenticateHeaderValue(parameters);
    response.addHeader("WWW-Authenticate", wwwAuthenticate);
    response.setStatus(HttpStatus.FORBIDDEN.value());

    // Custom Error Response
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    var authErrorResponse =
        new ApiErrorResponse(
            LocalDateTime.now().toString(),
            "APP403",
            "FORBIDDEN",
            accessDeniedException.getMessage()
                + ", insufficient scope or role: The request requires higher privileges than provided by the access token.");
    response.getWriter().write(objectMapper.writeValueAsString(authErrorResponse));
  }
}
