package com.fabfitfun;

import io.smallrye.mutiny.Uni;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

@Path("/hello-resteasy")
public class GreetingResource {

  @GET
  @Produces(MediaType.TEXT_PLAIN)
  public Uni<String> hello() {
    return Uni.createFrom().item("PEPE").onItem().transform(n -> String.format("hello %s", n));
    }
}


