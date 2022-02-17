/*
 * Copyright 2022 OpsMx, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.netflix.spinnaker.kork.secrets.engines;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.cloud.secretmanager.v1.*;
import com.netflix.spinnaker.kork.secrets.EncryptedSecret;
import com.netflix.spinnaker.kork.secrets.InvalidSecretFormatException;
import com.netflix.spinnaker.kork.secrets.SecretEngine;
import com.netflix.spinnaker.kork.secrets.SecretException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
public class GoogleSecretsManagerSecretEngine implements SecretEngine {
  protected static final String PROJECT_NUMBER = "p";
  protected static final String SECRET_ID = "s";
  protected static final String SECRET_KEY = "k";
  protected static final String VERSION_ID = "latest";

  private static String IDENTIFIER = "google-secrets-manager";

  private Map<String, Map<String, String>> cache = new HashMap<>();
  private static final ObjectMapper mapper = new ObjectMapper();

  @Override
  public String identifier() {
    return GoogleSecretsManagerSecretEngine.IDENTIFIER;
  }

  @Override
  public byte[] decrypt(EncryptedSecret encryptedSecret) {
    String projectNumber = encryptedSecret.getParams().get(PROJECT_NUMBER);
    String secretId = encryptedSecret.getParams().get(SECRET_ID);
    String secretKey = encryptedSecret.getParams().get(SECRET_KEY);
    if (encryptedSecret.isEncryptedFile()) {
      return getSecretValue(projectNumber, secretId).getBytes();
    } else if (secretKey != null) {
      return getSecretString(projectNumber, secretId, secretKey);
    } else {
      return getSecretString(projectNumber, secretId);
    }
  }

  @Override
  public void validate(EncryptedSecret encryptedSecret) {
    Set<String> paramNames = encryptedSecret.getParams().keySet();
    if (!paramNames.contains(PROJECT_NUMBER)) {
      throw new InvalidSecretFormatException(
          "Project id parameter is missing (" + PROJECT_NUMBER + "=...)");
    }
    if (!paramNames.contains(SECRET_ID)) {
      throw new InvalidSecretFormatException(
          "Secret id parameter is missing (" + SECRET_ID + "=...)");
    }
    if (encryptedSecret.isEncryptedFile() && paramNames.contains(SECRET_KEY)) {
      throw new InvalidSecretFormatException("Encrypted file should not specify key");
    }
  }

  protected String getSecretValue(String projectNumber, String secretId) {
    try (SecretManagerServiceClient client = SecretManagerServiceClient.create()) {
      SecretVersionName secretVersionName =
          SecretVersionName.of(projectNumber, secretId, VERSION_ID);
      AccessSecretVersionResponse response = client.accessSecretVersion(secretVersionName);
      return response.getPayload().getData().toStringUtf8();
    } catch (IOException e) {
      throw new SecretException(
          String.format(
              "Failed to parse secret when using Google Secrets Manager to fetch: [projectNumber: %s, secretId: %s]",
              projectNumber, secretId),
          e);
    }
  }

  @Override
  public void clearCache() {
    cache.clear();
  }

  private byte[] getSecretString(String projectNumber, String secretId, String secretKey) {
    if (!cache.containsKey(secretId)) {
      String secretString = getSecretValue(projectNumber, secretId);
      try {
        Map<String, String> map = mapper.readValue(secretString, Map.class);
        cache.put(secretId, map);
      } catch (JsonProcessingException | IllegalArgumentException e) {
        throw new SecretException(
            String.format(
                "Failed to parse secret when using Google Secrets Manager to fetch: [projectNumber: %s, secretId: %s, secretKey: %s]",
                projectNumber, secretId, secretKey),
            e);
      }
    }
    return Optional.ofNullable(cache.get(secretId).get(secretKey))
        .orElseThrow(
            () ->
                new SecretException(
                    String.format(
                        "Specified key not found in Google Secrets Manager: [projectNumber: %s, secretId: %s, secretKey: %s]",
                        projectNumber, secretId, secretKey)))
        .getBytes();
  }

  private byte[] getSecretString(String projectNumber, String secretId) {
    return getSecretValue(projectNumber, secretId).getBytes();
  }
}
