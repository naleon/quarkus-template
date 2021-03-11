package com.fabfitfun.api;

import com.fabfitfun.security.CustomDefaultCallerPrincipal;
import com.fabfitfun.service.UserService;
import io.smallrye.mutiny.Uni;
import lombok.val;
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


@Path("/")
public class User {

    private static final Logger LOG = Logger.getLogger(User.class);

    @Inject
    JsonWebToken jwt;

    @Inject
    UserService userService;

    @GET
    @Path("retrieve-email")
    @Produces(MediaType.APPLICATION_JSON)
    @RolesAllowed({ "Admin" })
    public Uni<String> getEmail(@Context SecurityContext ctx) {
        val user = (CustomDefaultCallerPrincipal)ctx.getUserPrincipal();
        return userService.retrieveUserEmail(user.getPushId());
    }
}
