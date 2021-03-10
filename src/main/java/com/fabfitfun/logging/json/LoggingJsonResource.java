package com.fabfitfun.logging.json;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;

import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;
import java.util.Set;


@Path("/logging-json")
public class LoggingJsonResource {

    private static final Logger LOG = Logger.getLogger(LoggingJsonResource.class);

    @Inject
    JsonWebToken jwt;

    @GET
    @Path("faster")
    @Produces(MediaType.APPLICATION_JSON)
    @RolesAllowed({ "Admin", "Role2" })
    public Set<String> faster(@Context SecurityContext ctx) {
        return jwt.getClaimNames();
    }
}
