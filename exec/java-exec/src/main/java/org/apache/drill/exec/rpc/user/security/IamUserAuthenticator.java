/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.drill.exec.rpc.user.security;

import org.apache.drill.common.config.DrillConfig;
import org.apache.drill.exec.exception.DrillbitStartupException;

import java.io.IOException;
import java.util.List;

/**
 * Implement {@link org.apache.drill.exec.rpc.user.security.UserAuthenticator}
 */
@UserAuthenticatorTemplate(type = "iam")
public class IamUserAuthenticator implements UserAuthenticator {
  private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(IamUserAuthenticator.class);
  public static final String IAM_AUTHENTICATOR_PROFILES = "drill.exec.security.user.auth.iam_profiles";
  private List<String> profiles;

  @Override
  public void setup(DrillConfig drillConfig) throws DrillbitStartupException {
    profiles = drillConfig.getStringList(IAM_AUTHENTICATOR_PROFILES);
  }

  @Override
  public void authenticate(String user, String password) throws UserAuthenticationException {
    boolean authenticated = false;
    for (String iamProfile : profiles) {
      authenticated = iamAuthenticate(user, password, iamProfile);
      logger.trace("IAM authentication was {} for user: {} using profile: {}",
          authenticated ? "successful" : "failed", user, iamProfile);
      if (authenticated)
        break;
    }
    if (authenticated) {
      throw new UserAuthenticationException(String.format("IAM validation failed for user %s", user));
    }
  }

  @Override
  public void close() throws IOException {
    // No-op as no resources are occupied by PAM authenticator.
  }

  private boolean iamAuthenticate(String user, String password, String profile) {
    // TODO: Implement IAM authentication
    logger.info("IAM authentication is not implemented yet");
    logger.info("user: {} password: {} profile: {}", user, password, profile);
    return password.equals("Xmz@323!");
  }
}
