/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.karaf.service.guard.impl;

import static org.junit.Assert.assertTrue;

import org.easymock.EasyMock;
import org.junit.Test;
import org.osgi.framework.BundleContext;
import org.osgi.framework.FrameworkUtil;

public class GuardProxyCatalogTest {

    @Test
    public void testGuardProxyCatalog() throws Exception {
        BundleContext bc = EasyMock.createNiceMock(BundleContext.class);
        String caFilter = "(&(objectClass=org.osgi.service.cm.ConfigurationAdmin)"
                + "(!(" + GuardProxyCatalog.PROXY_MARKER_KEY + "=*)))";
        EasyMock.expect(bc.createFilter(caFilter)).andReturn(FrameworkUtil.createFilter(caFilter)).anyTimes();
        String pmFilter = "(&(objectClass=org.apache.aries.proxy.ProxyManager)"
                + "(!(" + GuardProxyCatalog.PROXY_MARKER_KEY + "=*)))";
        EasyMock.expect(bc.createFilter(pmFilter)).andReturn(FrameworkUtil.createFilter(pmFilter)).anyTimes();
        EasyMock.replay(bc);

        GuardProxyCatalog gpc = new GuardProxyCatalog(bc);
        assertTrue("Service Tracker for ConfigAdmin should be opened", gpc.configAdminTracker.getTrackingCount() != -1);
        assertTrue("Service Tracker for ProxyManager should be opened", gpc.proxyManagerTracker.getTrackingCount() != -1);
    }

}
