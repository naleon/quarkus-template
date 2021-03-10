package com.fabfitfun.security.interceptor;

import io.quarkus.reactive.datasource.ReactiveDataSource;
import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.groups.MultiCollect;
import io.vertx.mutiny.sqlclient.Row;
import org.jboss.logging.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

@ApplicationScoped
public class SecurityBean {
  @Inject
  @ReactiveDataSource("ebdb")
  io.vertx.mutiny.mysqlclient.MySQLPool client;

  @Inject
  Logger logger;


  public void validateAccessRole(String role, PermissionLevel level, String id) {
    MultiCollect<Row> rows = client.query("SELECT id, title FROM acl_permissions").execute()
            .onItem().transformToMulti(set -> Multi.createFrom().iterable(set))
            .collect();
    long idFound = rows.first().await().indefinitely().getLong("id");
    logger.infof("id: %d",idFound);
  }
}
