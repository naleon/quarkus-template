package com.fabfitfun.security;

import io.netty.util.internal.StringUtil;
import io.smallrye.jwt.auth.principal.DefaultJWTCallerPrincipal;
import lombok.Data;
import lombok.Getter;
import lombok.extern.jbosslog.JBossLog;
import lombok.val;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;

import javax.ws.rs.Produces;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@JBossLog
@Getter
public class CustomDefaultCallerPrincipal extends DefaultJWTCallerPrincipal {
  private static final String ROLE_CLAIM = "roles";
  private boolean backendUser;
  private JwtClaims claimsSet;
  private Long pushId;
  private Long wooId;
  private UUID uuid;
  private String accountCode;

  public CustomDefaultCallerPrincipal(JwtClaims claimsSet) {
    super(claimsSet);
    this.claimsSet = claimsSet;
    initFFFPrincipalProperties();
  }

  private void initFFFPrincipalProperties() {
    try {
      // Backend users have a client id
      String clientId = claimsSet.getClaimValueAsString("clientId");
      if (!StringUtil.isNullOrEmpty(clientId)) {
        log.debug("Client: " + clientId);
        backendUser = true;
      } else {
        pushId = claimsSet.getClaimValue("pushId", Long.class);
        wooId = claimsSet.getClaimValue("wooId", Long.class);
        if (pushId == null) {
          throw new RuntimeException("JWT is missing push Id.");
        }
        if (pushId == null) {
          throw new RuntimeException("JWT is missing woo id.");
        }
        val uuidStr = claimsSet.getClaimValueAsString("id");
        uuid = (uuidStr == null) ? null : UUID.fromString((uuidStr));
        accountCode = claimsSet.getClaimValueAsString("accountCode");
        if (StringUtil.isNullOrEmpty(accountCode)) {
          // Either the claim "accountCode" in jwt is absent or it's value is null
          log.warnf("JWT contains no account code.");
        }
      }
    } catch (MalformedClaimException e) {
      throw new RuntimeException("Error building Principal from JWT.", e);
    }
  }

  @Override
  public Set<String> getGroups() {
    HashSet<String> groups = new HashSet<>();
    try {
      val roles = claimsSet.getStringListClaimValue(ROLE_CLAIM);
      roles.forEach(r -> groups.add(r));
      if (backendUser){
        groups.add("backend");
      }
    } catch (MalformedClaimException e) {
      log.error("Error parsing JWT claims", e);
    }
    return groups;
  }

  @Override
  protected Set<String> filterCustomClaimNames(Collection<String> claimNames) {
    return new HashSet<>();
  }

  @Produces
  public CustomDefaultCallerPrincipal fetch(){
    return this;
  }
}
