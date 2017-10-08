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
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.ranger.authorization.accumulo.authorizer;

import static java.nio.charset.StandardCharsets.UTF_8;

import org.apache.accumulo.core.client.AccumuloSecurityException;
import org.apache.accumulo.core.client.NamespaceNotFoundException;
import org.apache.accumulo.core.client.TableNotFoundException;
import org.apache.accumulo.core.client.impl.thrift.ThriftSecurityException;
import org.apache.accumulo.core.security.NamespacePermission;
import org.apache.accumulo.core.security.SystemPermission;
import org.apache.accumulo.core.security.TablePermission;
import org.apache.accumulo.core.security.thrift.TCredentials;
import org.apache.accumulo.core.util.Base64;
import org.apache.accumulo.server.security.handler.Authenticator;
import org.apache.accumulo.server.security.handler.Authorizor;
import org.apache.accumulo.server.security.handler.KerberosAuthenticator;
import org.apache.accumulo.server.security.handler.KerberosAuthorizor;
import org.apache.accumulo.server.security.handler.PermissionHandler;
import org.apache.accumulo.server.security.handler.ZKPermHandler;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ranger.audit.provider.MiscUtil;
import org.apache.ranger.authorization.hadoop.config.RangerConfiguration;
import org.apache.ranger.plugin.policyengine.RangerAccessRequest;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.service.RangerBasePlugin;

public class RangerAccumuloPermissionHandler implements PermissionHandler {

    private static final Log logger = LogFactory
            .getLog(RangerAccumuloPermissionHandler.class);

    public static final String PROP_USE_PROXY_IP = "xasecure.accumulo.use_proxy_ip";
    public static final String PROP_PROXY_IP_HEADER = "xasecure.solr.proxy_ip_header";
    public static final String PROP_SOLR_APP_NAME = "xasecure.accumulo.app.name";

    public static final String KEY_COLLECTION = "collection";

    public static final String ACCESS_TYPE_CREATE = "create";
    public static final String ACCESS_TYPE_UPDATE = "update";
    public static final String ACCESS_TYPE_QUERY = "query";

    protected static volatile RangerBasePlugin accumuloPlugin = null;

    boolean useProxyIP = false;
    String proxyIPHeader = "HTTP_X_FORWARDED_FOR";
    String accumuloAppName = "Client";

    private final ZKPermHandler zkPermissionHandler;

    public RangerAccumuloPermissionHandler() {
        zkPermissionHandler = new ZKPermHandler();
        logger.info("RangerAccumuloAuthorizer()");
    }

    @Override
    public void initialize(String instanceId, boolean initialize) {
        logger.info("init()");

        try {
            useProxyIP = RangerConfiguration.getInstance().getBoolean(
                    PROP_USE_PROXY_IP, useProxyIP);
            proxyIPHeader = RangerConfiguration.getInstance().get(
                    PROP_PROXY_IP_HEADER, proxyIPHeader);
            // First get from the -D property
            accumuloAppName = System.getProperty("accumulo.kerberos.jaas.appname",
                    accumuloAppName);
            // Override if required from Ranger properties
            accumuloAppName = RangerConfiguration.getInstance().get(
                    PROP_SOLR_APP_NAME, accumuloAppName);

            logger.info("init(): useProxyIP=" + useProxyIP);
            logger.info("init(): proxyIPHeader=" + proxyIPHeader);
            logger.info("init(): accumuloAppName=" + accumuloAppName);
            logger.info("init(): KerberosName.rules="
                    + MiscUtil.getKerberosNamesRules());

        } catch (Throwable t) {
            logger.fatal("Error init", t);
        }

        try {
            accumuloPlugin = new RangerBasePlugin("accumulo", "accumulo");
            accumuloPlugin.init();
        } catch (Throwable t) {
            logger.fatal("Error creating and initializing RangerBasePlugin()");
        }
    }

    @Override
    public boolean validSecurityHandlers(Authenticator authent, Authorizor author) {
        return authent instanceof KerberosAuthenticator && author instanceof KerberosAuthorizor;
    }

    @Override
    public void initializeSecurity(TCredentials credentials, String rootuser) throws AccumuloSecurityException, ThriftSecurityException {
        //zkPermissionHandler.initializeSecurity(credentials, Base64.encodeBase64String(rootuser.getBytes(UTF_8)));
    }

    @Override
    public boolean hasSystemPermission(String user, SystemPermission permission) throws AccumuloSecurityException {

        RangerAccessRequestImpl request = new RangerAccessRequestImpl();
        request.setAccessType(permission.toString());
        request.setUser(user);
        RangerAccessResourceImpl resource = new RangerAccessResourceImpl();
        resource.setValue("system", "*");
        request.setResource(resource);
        RangerAccessResult result = accumuloPlugin.isAccessAllowed(request);
        return result.getIsAllowed();

    }

    @Override
    public boolean hasCachedSystemPermission(String user, SystemPermission permission) throws AccumuloSecurityException {
        return hasSystemPermission(user, permission);
    }

    @Override
    public boolean hasTablePermission(String user, String table, TablePermission permission) throws AccumuloSecurityException, TableNotFoundException {
        RangerAccessRequestImpl request = new RangerAccessRequestImpl();
        request.setAccessType(permission.toString());
        request.setUser(user);
        RangerAccessResourceImpl resource = new RangerAccessResourceImpl();
        resource.setValue("table", table);
        request.setResource(resource);
        RangerAccessResult result = accumuloPlugin.isAccessAllowed(request);
        return result.getIsAllowed();
    }

    @Override
    public boolean hasCachedTablePermission(String user, String table, TablePermission permission) throws AccumuloSecurityException, TableNotFoundException {
        return hasTablePermission(user, table, permission);
    }

    @Override
    public boolean hasNamespacePermission(String user, String namespace, NamespacePermission permission) throws AccumuloSecurityException,
            NamespaceNotFoundException {
        return zkPermissionHandler.hasNamespacePermission(Base64.encodeBase64String(user.getBytes(UTF_8)), namespace, permission);
    }

    @Override
    public boolean hasCachedNamespacePermission(String user, String namespace, NamespacePermission permission) throws AccumuloSecurityException,
            NamespaceNotFoundException {
        return zkPermissionHandler.hasCachedNamespacePermission(Base64.encodeBase64String(user.getBytes(UTF_8)), namespace, permission);
    }

    @Override
    public void grantSystemPermission(String user, SystemPermission permission) throws AccumuloSecurityException {
        throw new UnsupportedOperationException("Cannot modify system permissions when using Ranger");
    }

    @Override
    public void revokeSystemPermission(String user, SystemPermission permission) throws AccumuloSecurityException {
        throw new UnsupportedOperationException("Cannot modify system permissions when using Ranger");
    }

    @Override
    public void grantTablePermission(String user, String table, TablePermission permission) throws AccumuloSecurityException, TableNotFoundException {
        throw new UnsupportedOperationException("Cannot modify table permissions when using Ranger");
    }

    @Override
    public void revokeTablePermission(String user, String table, TablePermission permission) throws AccumuloSecurityException, TableNotFoundException {
        throw new UnsupportedOperationException("Cannot modify table permissions when using Ranger");
    }

    @Override
    public void grantNamespacePermission(String user, String namespace, NamespacePermission permission) throws AccumuloSecurityException,
            NamespaceNotFoundException {
        throw new UnsupportedOperationException("Cannot modify namespace permissions when using Ranger");
    }

    @Override
    public void revokeNamespacePermission(String user, String namespace, NamespacePermission permission) throws AccumuloSecurityException,
            NamespaceNotFoundException {
        throw new UnsupportedOperationException("Cannot modify namespace permissions when using Ranger");
    }

    @Override
    public void cleanTablePermissions(String table) throws AccumuloSecurityException, TableNotFoundException {
        throw new UnsupportedOperationException("Cannot modify table permissions when using Ranger");
    }

    @Override
    public void cleanNamespacePermissions(String namespace) throws AccumuloSecurityException, NamespaceNotFoundException {
        throw new UnsupportedOperationException("Cannot modify namespace permissions when using Ranger");
    }

    @Override
    public void initUser(String user) throws AccumuloSecurityException {
        throw new UnsupportedOperationException("Cannot modify users when using Ranger");
    }

    @Override
    public void initTable(String table) throws AccumuloSecurityException {
        //nothing to be done
    }

    @Override
    public void cleanUser(String user) throws AccumuloSecurityException {
        throw new UnsupportedOperationException("Cannot modify users when using Ranger");
    }

}
