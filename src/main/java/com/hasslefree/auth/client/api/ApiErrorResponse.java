package com.hasslefree.auth.client.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;
import lombok.Builder;
import lombok.Value;

@Value
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiErrorResponse {
  String type;
  String title;
  int status;
  String detail;
  String instance;
  String traceId;
  List<InvalidParam> invalidParams;

  @Value
  @Builder
  public static class InvalidParam {
    String name;
    String reason;
  }
}
