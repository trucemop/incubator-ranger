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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.Reader;
import java.net.URL;
import org.apache.accumulo.core.security.NamespacePermission;
import org.apache.accumulo.core.security.SystemPermission;
import org.apache.accumulo.core.security.TablePermission;
import org.apache.ranger.plugin.util.PolicyRefresher;
import org.apache.ranger.plugin.util.ServicePolicies;
import org.junit.Test;
import static org.junit.Assert.*;

public class RangerAccumuloPermissionHandlerTest {

    public RangerAccumuloPermissionHandlerTest() {
    }

    @Test
    public void testAdminHasAllSystemPermissions() throws Exception {

        File file = new File(getClass().getResource(getClass().getSimpleName() + "/" + "adminHasAll_accumulo.json").getPath());

        Gson gson = new GsonBuilder().setDateFormat("yyyyMMdd-HH:mm:ss.SSS-Z").setPrettyPrinting().create();
        Reader reader = new FileReader(file);
        ServicePolicies policies = gson.fromJson(reader, ServicePolicies.class);
        RangerAccumuloPermissionHandler rap = new RangerAccumuloPermissionHandler();
        rap.initialize("accumulo", true);
        RangerAccumuloPermissionHandler.accumuloPlugin.setPolicies(policies);
        assertTrue(rap.hasSystemPermission("admin", SystemPermission.GRANT));
        assertTrue(rap.hasSystemPermission("admin", SystemPermission.CREATE_TABLE));
        assertTrue(rap.hasSystemPermission("admin", SystemPermission.DROP_TABLE));
        assertTrue(rap.hasSystemPermission("admin", SystemPermission.ALTER_TABLE));
        assertTrue(rap.hasSystemPermission("admin", SystemPermission.CREATE_USER));
        assertTrue(rap.hasSystemPermission("admin", SystemPermission.DROP_USER));
        assertTrue(rap.hasSystemPermission("admin", SystemPermission.ALTER_USER));
        assertTrue(rap.hasSystemPermission("admin", SystemPermission.SYSTEM));
        assertTrue(rap.hasSystemPermission("admin", SystemPermission.CREATE_NAMESPACE));
        assertTrue(rap.hasSystemPermission("admin", SystemPermission.DROP_NAMESPACE));
        assertTrue(rap.hasSystemPermission("admin", SystemPermission.ALTER_NAMESPACE));
        assertTrue(rap.hasSystemPermission("admin", SystemPermission.OBTAIN_DELEGATION_TOKEN));
    }

    @Test
    public void testUserDoesNotHaveSystemPermissions() throws Exception {

        File file = new File(getClass().getResource(getClass().getSimpleName() + "/" + "adminHasAll_accumulo.json").getPath());

        Gson gson = new GsonBuilder().setDateFormat("yyyyMMdd-HH:mm:ss.SSS-Z").setPrettyPrinting().create();
        Reader reader = new FileReader(file);
        ServicePolicies policies = gson.fromJson(reader, ServicePolicies.class);
        RangerAccumuloPermissionHandler rap = new RangerAccumuloPermissionHandler();
        rap.initialize("accumulo", true);
        RangerAccumuloPermissionHandler.accumuloPlugin.setPolicies(policies);
        assertFalse(rap.hasSystemPermission("joe", SystemPermission.GRANT));
        assertFalse(rap.hasSystemPermission("joe", SystemPermission.CREATE_TABLE));
        assertFalse(rap.hasSystemPermission("joe", SystemPermission.DROP_TABLE));
        assertFalse(rap.hasSystemPermission("joe", SystemPermission.ALTER_TABLE));
        assertFalse(rap.hasSystemPermission("joe", SystemPermission.CREATE_USER));
        assertFalse(rap.hasSystemPermission("joe", SystemPermission.DROP_USER));
        assertFalse(rap.hasSystemPermission("joe", SystemPermission.ALTER_USER));
        assertFalse(rap.hasSystemPermission("joe", SystemPermission.SYSTEM));
        assertFalse(rap.hasSystemPermission("joe", SystemPermission.CREATE_NAMESPACE));
        assertFalse(rap.hasSystemPermission("joe", SystemPermission.DROP_NAMESPACE));
        assertFalse(rap.hasSystemPermission("joe", SystemPermission.ALTER_NAMESPACE));
        assertFalse(rap.hasSystemPermission("joe", SystemPermission.OBTAIN_DELEGATION_TOKEN));
    }

    @Test
    public void testAdminHasAllTablePermission() throws Exception {
        File file = new File(getClass().getResource(getClass().getSimpleName() + "/" + "adminHasAll_accumulo.json").getPath());

        Gson gson = new GsonBuilder().setDateFormat("yyyyMMdd-HH:mm:ss.SSS-Z").setPrettyPrinting().create();
        Reader reader = new FileReader(file);
        ServicePolicies policies = gson.fromJson(reader, ServicePolicies.class);
        RangerAccumuloPermissionHandler rap = new RangerAccumuloPermissionHandler();
        rap.initialize("accumulo", true);
        RangerAccumuloPermissionHandler.accumuloPlugin.setPolicies(policies);
        assertTrue(rap.hasTablePermission("admin", "test", TablePermission.READ));
        assertTrue(rap.hasTablePermission("admin", "test", TablePermission.WRITE));
        assertTrue(rap.hasTablePermission("admin", "test", TablePermission.BULK_IMPORT));
        assertTrue(rap.hasTablePermission("admin", "test", TablePermission.ALTER_TABLE));
        assertTrue(rap.hasTablePermission("admin", "test", TablePermission.GRANT));
        assertTrue(rap.hasTablePermission("admin", "test", TablePermission.DROP_TABLE));
    }

    @Test
    public void testUserDoesNotHaveTablePermissions() throws Exception {
        File file = new File(getClass().getResource(getClass().getSimpleName() + "/" + "adminHasAll_accumulo.json").getPath());

        Gson gson = new GsonBuilder().setDateFormat("yyyyMMdd-HH:mm:ss.SSS-Z").setPrettyPrinting().create();
        Reader reader = new FileReader(file);
        ServicePolicies policies = gson.fromJson(reader, ServicePolicies.class);
        RangerAccumuloPermissionHandler rap = new RangerAccumuloPermissionHandler();
        rap.initialize("accumulo", true);
        RangerAccumuloPermissionHandler.accumuloPlugin.setPolicies(policies);
        assertFalse(rap.hasTablePermission("joe", "test", TablePermission.READ));
        assertFalse(rap.hasTablePermission("joe", "test", TablePermission.WRITE));
        assertFalse(rap.hasTablePermission("joe", "test", TablePermission.BULK_IMPORT));
        assertFalse(rap.hasTablePermission("joe", "test", TablePermission.ALTER_TABLE));
        assertFalse(rap.hasTablePermission("joe", "test", TablePermission.GRANT));
        assertFalse(rap.hasTablePermission("joe", "test", TablePermission.DROP_TABLE));
    }

    @Test
    public void testAdminHasAllNamespacePermissions() throws Exception {
        File file = new File(getClass().getResource(getClass().getSimpleName() + "/" + "adminHasAll_accumulo.json").getPath());

        Gson gson = new GsonBuilder().setDateFormat("yyyyMMdd-HH:mm:ss.SSS-Z").setPrettyPrinting().create();
        Reader reader = new FileReader(file);
        ServicePolicies policies = gson.fromJson(reader, ServicePolicies.class);
        RangerAccumuloPermissionHandler rap = new RangerAccumuloPermissionHandler();
        rap.initialize("accumulo", true);
        RangerAccumuloPermissionHandler.accumuloPlugin.setPolicies(policies);
        assertTrue(rap.hasNamespacePermission("admin", "testNamespace", NamespacePermission.READ));
        assertTrue(rap.hasNamespacePermission("admin", "testNamespace", NamespacePermission.WRITE));
        assertTrue(rap.hasNamespacePermission("admin", "testNamespace", NamespacePermission.ALTER_NAMESPACE));
        assertTrue(rap.hasNamespacePermission("admin", "testNamespace", NamespacePermission.GRANT));
        assertTrue(rap.hasNamespacePermission("admin", "testNamespace", NamespacePermission.ALTER_TABLE));
        assertTrue(rap.hasNamespacePermission("admin", "testNamespace", NamespacePermission.CREATE_TABLE));
        assertTrue(rap.hasNamespacePermission("admin", "testNamespace", NamespacePermission.DROP_TABLE));
        assertTrue(rap.hasNamespacePermission("admin", "testNamespace", NamespacePermission.BULK_IMPORT));
        assertTrue(rap.hasNamespacePermission("admin", "testNamespace", NamespacePermission.DROP_NAMESPACE));

    }

    @Test
    public void testUserDoesNotHaveNamespacePermissions() throws Exception {
        File file = new File(getClass().getResource(getClass().getSimpleName() + "/" + "adminHasAll_accumulo.json").getPath());

        Gson gson = new GsonBuilder().setDateFormat("yyyyMMdd-HH:mm:ss.SSS-Z").setPrettyPrinting().create();
        Reader reader = new FileReader(file);
        ServicePolicies policies = gson.fromJson(reader, ServicePolicies.class);
        RangerAccumuloPermissionHandler rap = new RangerAccumuloPermissionHandler();
        rap.initialize("accumulo", true);
        RangerAccumuloPermissionHandler.accumuloPlugin.setPolicies(policies);
        assertFalse(rap.hasNamespacePermission("joe", "testNamespace", NamespacePermission.READ));
        assertFalse(rap.hasNamespacePermission("joe", "testNamespace", NamespacePermission.WRITE));
        assertFalse(rap.hasNamespacePermission("joe", "testNamespace", NamespacePermission.ALTER_NAMESPACE));
        assertFalse(rap.hasNamespacePermission("joe", "testNamespace", NamespacePermission.GRANT));
        assertFalse(rap.hasNamespacePermission("joe", "testNamespace", NamespacePermission.ALTER_TABLE));
        assertFalse(rap.hasNamespacePermission("joe", "testNamespace", NamespacePermission.CREATE_TABLE));
        assertFalse(rap.hasNamespacePermission("joe", "testNamespace", NamespacePermission.DROP_TABLE));
        assertFalse(rap.hasNamespacePermission("joe", "testNamespace", NamespacePermission.BULK_IMPORT));
        assertFalse(rap.hasNamespacePermission("joe", "testNamespace", NamespacePermission.DROP_NAMESPACE));

    }

    @Test
    public void testCleanTablePermissions() throws Exception {
    }

    @Test
    public void testCleanNamespacePermissions() throws Exception {
    }

    @Test
    public void testInitUser() throws Exception {
    }

    @Test
    public void testInitTable() throws Exception {
    }

    @Test
    public void testCleanUser() throws Exception {
    }

}
