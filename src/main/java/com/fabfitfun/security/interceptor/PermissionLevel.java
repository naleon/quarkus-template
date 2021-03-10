package com.fabfitfun.security.interceptor;

public enum PermissionLevel {
  NONE(0),
  READ(1),
  ADD(2),
  EDIT(3),
  DELETE(4);

  private final int intValue;

  private PermissionLevel(int intValue) {
    this.intValue = intValue;
  }

  public int getIntValue() {
    return intValue;
  }
}
