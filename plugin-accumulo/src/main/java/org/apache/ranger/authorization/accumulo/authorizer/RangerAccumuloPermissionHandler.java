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

import com.google.common.base.Charsets;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.UnknownHostException;
import org.apache.accumulo.core.Constants;
import org.apache.accumulo.core.client.AccumuloSecurityException;
import org.apache.accumulo.core.client.NamespaceNotFoundException;
import org.apache.accumulo.core.client.TableNotFoundException;
import org.apache.accumulo.core.client.impl.thrift.ThriftSecurityException;
import org.apache.accumulo.core.security.NamespacePermission;
import org.apache.accumulo.core.security.SystemPermission;
import org.apache.accumulo.core.security.TablePermission;
import org.apache.accumulo.core.security.thrift.TCredentials;
import org.apache.accumulo.server.security.handler.Authenticator;
import org.apache.accumulo.server.security.handler.Authorizor;
import org.apache.accumulo.server.security.handler.KerberosAuthenticator;
import org.apache.accumulo.server.security.handler.KerberosAuthorizor;
import org.apache.accumulo.server.security.handler.PermissionHandler;
import org.apache.accumulo.server.zookeeper.ZooCache;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.security.authentication.util.KerberosName;
import org.apache.ranger.plugin.audit.RangerMultiResourceAuditHandler;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.service.RangerBasePlugin;

public class RangerAccumuloPermissionHandler implements PermissionHandler {

    private static final Log logger = LogFactory
            .getLog(RangerAccumuloPermissionHandler.class);
    protected final ZooCache zooCache;

    public static final String RESOURCE_KEY_SYSTEM = "system";
    public static final String RESOURCE_KEY_TABLE = "table";
    public static final String RESOURCE_KEY_NAMESPACE = "namespace";

    private String ZKTablePath;
    private String ZKNamespacePath;
    private String ipAddress;

    protected static volatile RangerBasePlugin accumuloPlugin = null;

    public RangerAccumuloPermissionHandler() {
        logger.info("RangerAccumuloAuthorizer()");
        zooCache = new ZooCache();
    }

    protected RangerAccumuloPermissionHandler(ZooCache zc) {
        zooCache = zc;
    }

    protected byte[] getTable(String tableId) {
        return zooCache.get(ZKTablePath + "/" + tableId + Constants.ZTABLE_NAME);
    }

    protected byte[] getNamespace(String namespaceId) {
        return zooCache.get(ZKNamespacePath + "/" + namespaceId + Constants.ZNAMESPACE_NAME);
    }

    @Override
    public void initialize(String instanceId, boolean initialize) {
        logger.info("init()");
        ZKTablePath = Constants.ZROOT + "/" + instanceId + Constants.ZTABLES;
        ZKNamespacePath = Constants.ZROOT + "/" + instanceId + Constants.ZNAMESPACES;
        String appType = System.getProperty("app");
        try {
            ipAddress = Inet4Address.getLocalHost().getHostAddress();
        } catch (UnknownHostException ex) {
        }
        if (appType == null) {
            appType = "accumulo";
        }
        logger.info("AppType: " + appType);
        try {

            accumuloPlugin = new RangerBasePlugin("accumulo", appType);
            accumuloPlugin.init();
        } catch (Throwable t) {
            logger.fatal("Error creating and initializing RangerBasePlugin()", t);
        }
    }

    @Override
    public boolean validSecurityHandlers(Authenticator authent, Authorizor author) {
        return authent instanceof KerberosAuthenticator && author instanceof KerberosAuthorizor;
    }

    @Override
    public void initializeSecurity(TCredentials credentials, String rootuser) throws AccumuloSecurityException, ThriftSecurityException {
    }

    @Override
    public boolean hasSystemPermission(String user, SystemPermission permission) throws AccumuloSecurityException {

        boolean isAllowed = false;
        RangerAccessRequestImpl request = new RangerAccessRequestImpl();
        RangerMultiResourceAuditHandler auditHandler = new RangerMultiResourceAuditHandler();
        request.setAccessType(permission.toString());
        request.setAction(permission.toString());
        request.setUser(getShortname(user));
        request.setRemoteIPAddress(ipAddress);
        RangerAccessResourceImpl resource = new RangerAccessResourceImpl();
        resource.setValue(RESOURCE_KEY_SYSTEM, RESOURCE_KEY_SYSTEM);
        request.setResource(resource);
        RangerAccessResult result = null;
        try {
            result = accumuloPlugin.isAccessAllowed(request, auditHandler);
        } finally {
            auditHandler.flushAudit();
        }
        if (result != null) {
            isAllowed = result.getIsAllowed();
        }
        return isAllowed;

    }

    @Override
    public boolean hasCachedSystemPermission(String user, SystemPermission permission) throws AccumuloSecurityException {
        return hasSystemPermission(user, permission);
    }

    @Override
    public boolean hasTablePermission(String user, String table, TablePermission permission) throws AccumuloSecurityException, TableNotFoundException {
        boolean isAllowed = false;
        String tableName = table;
        RangerAccessRequestImpl request = new RangerAccessRequestImpl();
        RangerMultiResourceAuditHandler auditHandler = new RangerMultiResourceAuditHandler();
        request.setAccessType(permission.toString());
        request.setAction(permission.toString());
        request.setUser(getShortname(user));
        request.setRemoteIPAddress(ipAddress);
        byte[] tableBytes = getTable(table);

        if (tableBytes != null) {
            tableName = new String(tableBytes, Charsets.UTF_8);
        }

        RangerAccessResourceImpl resource = new RangerAccessResourceImpl();
        resource.setValue(RESOURCE_KEY_TABLE, tableName);
        request.setResource(resource);

        RangerAccessResult result = null;
        try {
            result = accumuloPlugin.isAccessAllowed(request, auditHandler);
        } finally {
            auditHandler.flushAudit();
        }
        if (result != null) {
            isAllowed = result.getIsAllowed();
        }
        return isAllowed;
    }

    @Override
    public boolean hasCachedTablePermission(String user, String table, TablePermission permission) throws AccumuloSecurityException, TableNotFoundException {
        return hasTablePermission(user, table, permission);
    }

    @Override
    public boolean hasNamespacePermission(String user, String namespace, NamespacePermission permission) throws AccumuloSecurityException,
            NamespaceNotFoundException {
        boolean isAllowed = false;

        String namespaceName = namespace;

        RangerAccessRequestImpl request = new RangerAccessRequestImpl();
        RangerMultiResourceAuditHandler auditHandler = new RangerMultiResourceAuditHandler();
        request.setAccessType(permission.toString());
        request.setAction(permission.toString());
        request.setUser(getShortname(user));
        request.setRemoteIPAddress(ipAddress);

        RangerAccessResourceImpl resource = new RangerAccessResourceImpl();

        byte[] namespaceBytes = getNamespace(namespace);

        if (namespaceBytes != null) {
            namespaceName = new String(namespaceBytes, Charsets.UTF_8);
        }

        resource.setValue(RESOURCE_KEY_NAMESPACE, namespaceName);
        request.setResource(resource);
        RangerAccessResult result = null;
        try {
            result = accumuloPlugin.isAccessAllowed(request, auditHandler);
        } finally {
            auditHandler.flushAudit();
        }
        if (result != null) {
            isAllowed = result.getIsAllowed();
        }
        return isAllowed;
    }

    @Override
    public boolean hasCachedNamespacePermission(String user, String namespace, NamespacePermission permission) throws AccumuloSecurityException,
            NamespaceNotFoundException {
        return hasNamespacePermission(user, namespace, permission);
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
    }

    @Override
    public void revokeTablePermission(String user, String table, TablePermission permission) throws AccumuloSecurityException, TableNotFoundException {
        throw new UnsupportedOperationException("Cannot modify table permissions when using Ranger");
    }

    @Override
    public void grantNamespacePermission(String user, String namespace, NamespacePermission permission) throws AccumuloSecurityException,
            NamespaceNotFoundException {
    }

    @Override
    public void revokeNamespacePermission(String user, String namespace, NamespacePermission permission) throws AccumuloSecurityException,
            NamespaceNotFoundException {
        throw new UnsupportedOperationException("Cannot modify namespace permissions when using Ranger");
    }

    @Override
    public void cleanTablePermissions(String table) throws AccumuloSecurityException, TableNotFoundException {
    }

    @Override
    public void cleanNamespacePermissions(String namespace) throws AccumuloSecurityException, NamespaceNotFoundException {
    }

    @Override
    public void initUser(String user) throws AccumuloSecurityException {
        //nothing to be done
    }

    @Override
    public void initTable(String table) throws AccumuloSecurityException {
        //nothing to be done
    }

    @Override
    public void cleanUser(String user) throws AccumuloSecurityException {
        //nothing to be done
    }

    protected String getShortname(String user) {
        KerberosName name = new KerberosName(user);
        String shortname = null;
        try {
            shortname = name.getShortName();
        } catch (IOException ex) {
            shortname = user;
        }
        return shortname;
    }
}
