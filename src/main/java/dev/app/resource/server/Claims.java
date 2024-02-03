package dev.app.resource.server;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Claims {

  String sub;
  String aud;
  String uid;
  String givenName;
  String sn;
  String ecenteraccountname;
  String providerid;
  String mail;
  String displayName;
  String app;
  String env;
  String scp;
  Long iat;
  Long exp;
  Long nbf;
}
