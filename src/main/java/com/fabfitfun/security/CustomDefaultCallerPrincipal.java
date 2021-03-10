package com.fabfitfun.security;

import io.smallrye.jwt.auth.principal.DefaultJWTCallerPrincipal;
import lombok.extern.jbosslog.JBossLog;
import lombok.val;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@JBossLog
public class CustomDefaultCallerPrincipal extends DefaultJWTCallerPrincipal {
  private static final String ROLE_CLAIM = "roles";
  private JwtClaims claimsSet;

  public CustomDefaultCallerPrincipal(JwtClaims claimsSet) {
    super(claimsSet);
    this.claimsSet = claimsSet;
  }

  @Override
  public Set<String> getGroups() {
    HashSet<String> groups = new HashSet<>();
    try {
      val roles = claimsSet.getStringListClaimValue(ROLE_CLAIM);
      roles.forEach(r -> groups.add(r));
    } catch (MalformedClaimException e) {
      log.error("Error parsing JWT claims", e);
    }
    return groups;
  }

  @Override
  protected Set<String> filterCustomClaimNames(Collection<String> claimNames) {
    return new HashSet<>();
  }
}
