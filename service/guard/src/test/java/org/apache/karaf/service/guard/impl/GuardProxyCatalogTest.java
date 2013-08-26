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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Collections;
import java.util.Dictionary;
import java.util.Hashtable;

import org.apache.aries.proxy.ProxyManager;
import org.apache.aries.proxy.impl.AsmProxyManager;
import org.apache.karaf.service.guard.impl.GuardProxyCatalog.CreateProxyRunnable;
import org.easymock.EasyMock;
import org.easymock.IAnswer;
import org.junit.Test;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.Filter;
import org.osgi.framework.FrameworkUtil;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceReference;

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

        gpc.close();
        assertEquals("Service Tracker for ConfigAdmin should be closed", -1, gpc.configAdminTracker.getTrackingCount());
        assertEquals("Service Tracker for ProxyManager should be closed", -1, gpc.proxyManagerTracker.getTrackingCount());
    }

    @Test
    public void testIsProxy() throws Exception {
        BundleContext bc = mockBundleContext();

        GuardProxyCatalog gpc = new GuardProxyCatalog(bc);

        Dictionary<String, Object> props = new Hashtable<String, Object>();
        props.put(GuardProxyCatalog.PROXY_MARKER_KEY, 12L);
        assertTrue(gpc.isProxy(mockServiceReference(props)));
        assertFalse(gpc.isProxy(mockServiceReference(new Hashtable<String, Object>())));
    }

    @Test
    public void testIsProxyForBundle() throws Exception {
        BundleContext bc = mockBundleContext();

        GuardProxyCatalog gpc = new GuardProxyCatalog(bc);

        Bundle bundle = EasyMock.createMock(Bundle.class);
        EasyMock.expect(bundle.getBundleId()).andReturn(42L).anyTimes();
        EasyMock.replay(bundle);

        BundleContext testBC = EasyMock.createMock(BundleContext.class);
        EasyMock.expect(testBC.getBundle()).andReturn(bundle).anyTimes();
        EasyMock.replay(testBC);

        Dictionary<String, Object> props1 = new Hashtable<String, Object>();
        props1.put(GuardProxyCatalog.PROXY_MARKER_KEY, 42L);
        assertTrue(gpc.isProxyFor(mockServiceReference(props1), testBC));
        Dictionary<String, Object> props2 = new Hashtable<String, Object>();
        props2.put(GuardProxyCatalog.PROXY_MARKER_KEY, 43L);
        assertFalse(gpc.isProxyFor(mockServiceReference(props2), testBC));
        assertFalse(gpc.isProxyFor(mockServiceReference(new Hashtable<String, Object>()), testBC));
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    @Test
    public void testCreateProxy() throws Exception {
        BundleContext bc = mockBundleContext();

        GuardProxyCatalog gpc = new GuardProxyCatalog(bc);

        BundleContext providerBC = EasyMock.createMock(BundleContext.class);
        // This will check that the right proxy is being registered.
        Dictionary<String, Object> proxyProps = new Hashtable<String, Object>();
        proxyProps.put("foo", "bar"); // TODO !!!
        EasyMock.expect(providerBC.registerService(
                EasyMock.aryEq(new String [] {TestServiceAPI.class.getName()}),
                EasyMock.isA(TestServiceAPI.class), EasyMock.eq(proxyProps))).andReturn(null).once();
        EasyMock.replay(providerBC);

        Bundle providerBundle = EasyMock.createMock(Bundle.class);
        EasyMock.expect(providerBundle.getBundleContext()).andReturn(providerBC).anyTimes();
        EasyMock.replay(providerBundle);

        final Dictionary<String, Object> props = new Hashtable<String, Object>();
        props.put(Constants.OBJECTCLASS, new String [] {TestServiceAPI.class.getName()});
        ServiceReference<TestServiceAPI> sr = EasyMock.createMock(ServiceReference.class);
        EasyMock.expect(sr.getPropertyKeys()).andReturn(
                Collections.list(props.keys()).toArray(new String [] {})).anyTimes();
        EasyMock.expect(sr.getProperty(EasyMock.isA(String.class))).andAnswer(new IAnswer<Object>() {
            @Override
            public Object answer() throws Throwable {
                return props.get(EasyMock.getCurrentArguments()[0]);
            }
        }).anyTimes();
        EasyMock.expect(sr.getBundle()).andReturn(providerBundle).anyTimes();
        EasyMock.replay(sr);

        Bundle clientBundle = EasyMock.createMock(Bundle.class);
        EasyMock.expect(clientBundle.getBundleId()).andReturn(999L).anyTimes();
        EasyMock.expect(clientBundle.loadClass(TestServiceAPI.class.getName())).andReturn((Class) TestServiceAPI.class).anyTimes();
        EasyMock.replay(clientBundle);

        BundleContext clientBC = EasyMock.createMock(BundleContext.class);
        EasyMock.expect(clientBC.getBundle()).andReturn(clientBundle).anyTimes();
        EasyMock.expect(clientBC.getService(sr)).andReturn(new TestService()).anyTimes();
        EasyMock.replay(clientBC);

        assertEquals("Precondition", 0, gpc.proxyMap.size());
        assertEquals("Precondition", 0, gpc.createProxyQueue.size());
        gpc.proxyIfNotAlreadyProxied(sr, clientBC);
        assertEquals(1, gpc.proxyMap.size());

        GuardProxyCatalog.ServiceRegistrationHolder holder = gpc.proxyMap.get(new GuardProxyCatalog.ProxyMapKey(sr, clientBC));
        assertNull("The registration shouldn't have happened yet", holder.registration);
        assertEquals(1, gpc.createProxyQueue.size());

        CreateProxyRunnable runnable = gpc.createProxyQueue.take();
        ProxyManager pm = getProxyManager();
        runnable.run(pm);
        ServiceReference<?> proxySR = holder.registration.getReference();
        // check proxySR

        // Check that the proxy registration was done on the original provider bundle's context
        EasyMock.verify(providerBC);
    }

    private ProxyManager getProxyManager() {
        return new AsmProxyManager();
    }

    private BundleContext mockBundleContext() throws InvalidSyntaxException {
        BundleContext bc = EasyMock.createNiceMock(BundleContext.class);
        EasyMock.expect(bc.createFilter(EasyMock.isA(String.class))).andAnswer(new IAnswer<Filter>() {
            @Override
            public Filter answer() throws Throwable {
                return FrameworkUtil.createFilter((String) EasyMock.getCurrentArguments()[0]);
            }
        }).anyTimes();
        EasyMock.replay(bc);
        return bc;
    }

    private ServiceReference<?> mockServiceReference(final Dictionary<String, Object> props) {
        return mockServiceReference(props, Object.class);
    }

    private <T> ServiceReference<T> mockServiceReference(final Dictionary<String, Object> props, Class<T> cls) {
        @SuppressWarnings("unchecked")
        ServiceReference<T> sr = EasyMock.createMock(ServiceReference.class);

        EasyMock.expect(sr.getPropertyKeys()).andReturn(
                Collections.list(props.keys()).toArray(new String [] {})).anyTimes();
        EasyMock.expect(sr.getProperty(EasyMock.isA(String.class))).andAnswer(new IAnswer<Object>() {
            @Override
            public Object answer() throws Throwable {
                return props.get(EasyMock.getCurrentArguments()[0]);
            }
        }).anyTimes();
        EasyMock.replay(sr);
        return sr;
    }

    public interface TestServiceAPI {
        public void doit();
    }

    public class TestService implements TestServiceAPI {
        @Override
        public void doit() {
            System.out.println("Doing it");
        }
    }
}
