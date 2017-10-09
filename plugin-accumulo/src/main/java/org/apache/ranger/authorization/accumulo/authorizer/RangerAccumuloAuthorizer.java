/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.apache.ranger.authorization.accumulo.authorizer;

import org.apache.accumulo.server.security.handler.Authenticator;
import org.apache.accumulo.server.security.handler.KerberosAuthenticator;
import org.apache.accumulo.server.security.handler.KerberosAuthorizor;
import org.apache.accumulo.server.security.handler.PermissionHandler;

public class RangerAccumuloAuthorizer extends KerberosAuthorizor {

    @Override
    public boolean validSecurityHandlers(Authenticator auth, PermissionHandler pm) {
        return auth instanceof KerberosAuthenticator && pm instanceof RangerAccumuloPermissionHandler;
    }
}
