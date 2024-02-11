package dev.app.resource.server;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * @author Anish Panthi
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Group(String client, String role) {}
