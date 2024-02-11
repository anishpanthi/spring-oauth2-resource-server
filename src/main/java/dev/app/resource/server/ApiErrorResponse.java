package dev.app.resource.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;

/**
 * @param timeStamp  - String
 * @param errorCode  - String
 * @param resultType - String
 * @param apiMessage - String
 */
public record ApiErrorResponse(
    String timeStamp, String errorCode, String resultType, String apiMessage) {

  @Override
  @SneakyThrows
  public String toString() {
    return new ObjectMapper().writeValueAsString(this);
  }
}
