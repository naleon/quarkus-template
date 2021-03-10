package com.fabfitfun.security.interceptor;

import javax.inject.Inject;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.annotation.Priority;
import javax.interceptor.InvocationContext;

import org.jboss.logging.Logger;

@PermissionAllowed
@Priority(2020)
@Interceptor
public class PermissionInterceptor {
  @Inject
  Logger logger;

  @Inject
  SecurityBean securityBean;

  @AroundInvoke
  Object permissionCheck(InvocationContext context) throws Exception {
    PermissionAllowed annotation = context.getMethod().getAnnotation(PermissionAllowed.class);
    String id = annotation.id();
    PermissionLevel level = annotation.level();
    logger.infof("Level %s", String.valueOf(level));
    logger.infof("id %s", id);
    securityBean.validateAccessRole("role", level, id);
   // client.query("").execute();

    Object ret = context.proceed();
    logger.info("Security interceptor called");
    return ret;
  }
}


