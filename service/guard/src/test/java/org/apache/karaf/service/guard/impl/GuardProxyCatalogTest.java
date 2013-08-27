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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Collections;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.Map;

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
import org.osgi.framework.ServiceRegistration;
import org.osgi.framework.wiring.BundleWiring;

public class GuardProxyCatalogTest {
    // Some assertions fail when run under a coverage tool, they are skipped when this is set to true
    private static final boolean runningUnderCoverage = false;

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

    @Test
    public void testCreateProxy() throws Exception {
        // This method tests proxy creation for various service implementation types.

//        testCreateProxy(TestServiceAPI.class, new TestService());
//        testCreateProxy(TestServiceAPI.class, new DescendantTestService());
//        testCreateProxy(TestServiceAPI.class, new PrivateTestService());
//        testCreateProxy(TestServiceAPI.class, new PrivateTestServiceNoDirectInterfaces());
//        testCreateProxy(TestServiceAPI.class, new FinalTestService());
        testCreateProxy(TestObjectWithoutInterface.class, new TestObjectWithoutInterface());
        testCreateProxy(TestServiceAPI.class, new CombinedTestService());
        testCreateProxy(PrivateTestService.class, Object.class, new PrivateTestService());
        testCreateProxy(PrivateTestServiceNoDirectInterfaces.class, Object.class, new PrivateTestServiceNoDirectInterfaces());
        testCreateProxy(Object.class, new TestService());
        testCreateProxy(Object.class, new DescendantTestService());
        testCreateProxy(Object.class, new PrivateTestService());
        testCreateProxy(Object.class, new TestObjectWithoutInterface());
        testCreateProxy(Object.class, new CombinedTestService());
        testCreateProxy(Object.class, new FinalTestService());
        testCreateProxy(TestServiceAPI.class, new TestServiceAPI() {
            @Override
            public String doit() {
                return "Doing it";
            }
        });
    }

    @Test
    public void testCreateProxyMultipleObjectClasses() throws Exception {
        testCreateProxy(new Class [] {TestServiceAPI.class, TestService.class}, new TestService());
    }

    @SuppressWarnings("rawtypes")
    public void testCreateProxy(final Class intf, Object testService) throws Exception {
        testCreateProxy(intf, intf, testService);
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    public void testCreateProxy(Class intf, final Class proxyRegClass, Object testService) throws Exception {
        BundleContext bc = mockBundleContext();

        // Create the object that is actually being tested here
        GuardProxyCatalog gpc = new GuardProxyCatalog(bc);

        // The service being proxied has these properties
        final Hashtable<String, Object> serviceProps = new Hashtable<String, Object>();
        serviceProps.put(Constants.OBJECTCLASS, new String [] {intf.getName()});
        serviceProps.put(".foo", 123L);

        final Map<ServiceReference<?>, Object> serviceMap = new HashMap<ServiceReference<?>, Object>();

        // The mock bundle context for the bundle providing the service is set up here
        BundleContext providerBC = EasyMock.createMock(BundleContext.class);
        // These are the expected service properties of the proxy registration. Note the proxy marker...
        Hashtable<String, Object> proxyProps = new Hashtable<String, Object>(serviceProps);
        proxyProps.put(GuardProxyCatalog.PROXY_MARKER_KEY, 999L);
        // This will check that the right proxy is being registered.
        EasyMock.expect(providerBC.registerService(
                EasyMock.isA(String[].class),
                EasyMock.anyObject(), EasyMock.eq(proxyProps))).andAnswer(new IAnswer() {
                    @Override
                    public ServiceRegistration answer() throws Throwable {
                        if (!runningUnderCoverage) {
                            // Some of these checks don't work when running under coverage
                            assertArrayEquals(new String [] {proxyRegClass.getName()},
                                    (String []) EasyMock.getCurrentArguments()[0]);

                            Object svc = EasyMock.getCurrentArguments()[1];
                            assertTrue(proxyRegClass.isAssignableFrom(svc.getClass()));
                        }

                        Dictionary<String,Object> props = (Dictionary<String, Object>) EasyMock.getCurrentArguments()[2];

                        ServiceRegistration reg = EasyMock.createMock(ServiceRegistration.class);
                        ServiceReference sr = mockServiceReference(props);
                        EasyMock.expect(reg.getReference()).andReturn(sr).anyTimes();
                        reg.unregister();
                        EasyMock.expectLastCall().once();
                        EasyMock.replay(reg);

                        serviceMap.put(sr, EasyMock.getCurrentArguments()[1]);

                        return reg;
                    }
                }).once();
        EasyMock.expect(providerBC.getService(EasyMock.isA(ServiceReference.class))).andAnswer(new IAnswer<Object>() {
            @Override
            public Object answer() throws Throwable {
                return serviceMap.get(EasyMock.getCurrentArguments()[0]);
            }
        }).anyTimes();
        EasyMock.replay(providerBC);

        // In some cases the proxy-creating code is looking for a classloader (e.g. when run through
        // a coverage tool such as EclEmma). This will satisfy that.
        BundleWiring bw = EasyMock.createMock(BundleWiring.class);
        EasyMock.expect(bw.getClassLoader()).andReturn(getClass().getClassLoader()).anyTimes();
        EasyMock.replay(bw);

        // The mock bundle that provides the original service (and also the proxy is registered with this)
        Bundle providerBundle = EasyMock.createNiceMock(Bundle.class);
        EasyMock.expect(providerBundle.getBundleContext()).andReturn(providerBC).anyTimes();
        EasyMock.expect(providerBundle.adapt(BundleWiring.class)).andReturn(bw).anyTimes();
        EasyMock.replay(providerBundle);

        ServiceReference sr = mockServiceReference(providerBundle, serviceProps);

        // The mock bundle that consumes the service
        Bundle clientBundle = EasyMock.createNiceMock(Bundle.class);
        EasyMock.expect(clientBundle.getBundleId()).andReturn(999L).anyTimes();
        EasyMock.expect(clientBundle.loadClass(intf.getName())).andReturn(intf).anyTimes();
        EasyMock.replay(clientBundle);

        // The mock bundle context for the client bundle
        BundleContext clientBC = EasyMock.createMock(BundleContext.class);
        EasyMock.expect(clientBC.getBundle()).andReturn(clientBundle).anyTimes();
        EasyMock.expect(clientBC.getService(sr)).andReturn(testService).anyTimes();
        EasyMock.replay(clientBC);

        assertEquals("Precondition", 0, gpc.proxyMap.size());
        assertEquals("Precondition", 0, gpc.createProxyQueue.size());
        // Create the proxy for the service
        gpc.proxyIfNotAlreadyProxied(sr, clientBC);
        assertEquals(1, gpc.proxyMap.size());

        // The actual proxy creation is done asynchronously.
        GuardProxyCatalog.ServiceRegistrationHolder holder = gpc.proxyMap.get(new GuardProxyCatalog.ProxyMapKey(sr, clientBC));
        assertNull("The registration shouldn't have happened yet", holder.registration);
        assertEquals(1, gpc.createProxyQueue.size());

        // Mimic the thread that works the queue to create the proxy
        CreateProxyRunnable runnable = gpc.createProxyQueue.take();
        ProxyManager pm = getProxyManager();
        runnable.run(pm);

        // The runnable should have put the actual registration in the holder
        ServiceReference<?> proxySR = holder.registration.getReference();
        for (String key : proxyProps.keySet()) {
            assertEquals(proxyProps.get(key), proxySR.getProperty(key));
        }

        // Check that the proxy registration was done on the original provider bundle's context
        EasyMock.verify(providerBC);

        // Test that the actual proxy invokes the original service...
        Object proxyService = serviceMap.get(proxySR);
        assertNotSame("The proxy should not be the same object as the original service", testService, proxyService);
        if (testService instanceof TestServiceAPI) {
            assertEquals("Doing it", ((TestServiceAPI) proxyService).doit());
        }
        if (testService instanceof TestObjectWithoutInterface) {
            if (!runningUnderCoverage) {
                assertEquals(-42L, ((TestObjectWithoutInterface) proxyService).compute(42L));
            }
        }

        gpc.close();
        EasyMock.verify(holder.registration); // checks that the unregister call was made
    }

    public void testCreateProxy(Class<?> [] objectClasses, Object testService) throws Exception {
        testCreateProxy(objectClasses, objectClasses, testService);
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    public void testCreateProxy(Class [] objectClasses, final Class [] proxyRegClasses, Object testService) throws Exception {
        // A linked hash map to keep iteration order over the keys predictable
        final LinkedHashMap<String, Class> objClsMap = new LinkedHashMap<String, Class>();
        for (Class cls : objectClasses) {
            objClsMap.put(cls.getName(), cls);
        }

        // A linked hash map to keep iteration order over the keys predictable
        final LinkedHashMap<String, Class> proxyRegClsMap = new LinkedHashMap<String, Class>();
        for (Class cls : proxyRegClasses) {
            proxyRegClsMap.put(cls.getName(), cls);
        }

        BundleContext bc = mockBundleContext();

        // Create the object that is actually being tested here
        GuardProxyCatalog gpc = new GuardProxyCatalog(bc);

        // The service being proxied has these properties
        final Hashtable<String, Object> serviceProps = new Hashtable<String, Object>();
        serviceProps.put(Constants.OBJECTCLASS, objClsMap.keySet().toArray(new String [] {}));
        serviceProps.put(".foo", 123L);

        final Map<ServiceReference<?>, Object> serviceMap = new HashMap<ServiceReference<?>, Object>();

        // The mock bundle context for the bundle providing the service is set up here
        BundleContext providerBC = EasyMock.createMock(BundleContext.class);
        // These are the expected service properties of the proxy registration. Note the proxy marker...
        Hashtable<String, Object> proxyProps = new Hashtable<String, Object>(serviceProps);
        proxyProps.put(GuardProxyCatalog.PROXY_MARKER_KEY, 999L);
        // This will check that the right proxy is being registered.
        EasyMock.expect(providerBC.registerService(
                EasyMock.isA(String[].class),
                EasyMock.anyObject(), EasyMock.eq(proxyProps))).andAnswer(new IAnswer() {
                    @Override
                    public ServiceRegistration answer() throws Throwable {
                        if (!runningUnderCoverage) {
                            // Some of these checks don't work when running under coverage
                            assertArrayEquals(proxyRegClsMap.keySet().toArray(new String [] {}),
                                    (String []) EasyMock.getCurrentArguments()[0]);

                            Object svc = EasyMock.getCurrentArguments()[1];
                            for (Class<?> proxyRegClass : proxyRegClsMap.values()) {
                                assertTrue(proxyRegClass.isAssignableFrom(svc.getClass()));
                            }
                        }

                        Dictionary<String,Object> props = (Dictionary<String, Object>) EasyMock.getCurrentArguments()[2];

                        ServiceRegistration reg = EasyMock.createMock(ServiceRegistration.class);
                        ServiceReference sr = mockServiceReference(props);
                        EasyMock.expect(reg.getReference()).andReturn(sr).anyTimes();
                        reg.unregister();
                        EasyMock.expectLastCall().once();
                        EasyMock.replay(reg);

                        serviceMap.put(sr, EasyMock.getCurrentArguments()[1]);

                        return reg;
                    }
                }).once();
        EasyMock.expect(providerBC.getService(EasyMock.isA(ServiceReference.class))).andAnswer(new IAnswer<Object>() {
            @Override
            public Object answer() throws Throwable {
                return serviceMap.get(EasyMock.getCurrentArguments()[0]);
            }
        }).anyTimes();
        EasyMock.replay(providerBC);

        // In some cases the proxy-creating code is looking for a classloader (e.g. when run through
        // a coverage tool such as EclEmma). This will satisfy that.
        BundleWiring bw = EasyMock.createMock(BundleWiring.class);
        EasyMock.expect(bw.getClassLoader()).andReturn(getClass().getClassLoader()).anyTimes();
        EasyMock.replay(bw);

        // The mock bundle that provides the original service (and also the proxy is registered with this)
        Bundle providerBundle = EasyMock.createNiceMock(Bundle.class);
        EasyMock.expect(providerBundle.getBundleContext()).andReturn(providerBC).anyTimes();
        EasyMock.expect(providerBundle.adapt(BundleWiring.class)).andReturn(bw).anyTimes();
        EasyMock.replay(providerBundle);

        ServiceReference sr = mockServiceReference(providerBundle, serviceProps);

        // The mock bundle that consumes the service
        Bundle clientBundle = EasyMock.createNiceMock(Bundle.class);
        EasyMock.expect(clientBundle.getBundleId()).andReturn(999L).anyTimes();
        EasyMock.expect(clientBundle.loadClass(EasyMock.isA(String.class))).andAnswer(new IAnswer() {
            @Override
            public Class answer() throws Throwable {
                return objClsMap.get(EasyMock.getCurrentArguments()[0]);
            }
        }).anyTimes();
        EasyMock.replay(clientBundle);

        // The mock bundle context for the client bundle
        BundleContext clientBC = EasyMock.createMock(BundleContext.class);
        EasyMock.expect(clientBC.getBundle()).andReturn(clientBundle).anyTimes();
        EasyMock.expect(clientBC.getService(sr)).andReturn(testService).anyTimes();
        EasyMock.replay(clientBC);

        assertEquals("Precondition", 0, gpc.proxyMap.size());
        assertEquals("Precondition", 0, gpc.createProxyQueue.size());
        // Create the proxy for the service
        gpc.proxyIfNotAlreadyProxied(sr, clientBC);
        assertEquals(1, gpc.proxyMap.size());

        // The actual proxy creation is done asynchronously.
        GuardProxyCatalog.ServiceRegistrationHolder holder = gpc.proxyMap.get(new GuardProxyCatalog.ProxyMapKey(sr, clientBC));
        assertNull("The registration shouldn't have happened yet", holder.registration);
        assertEquals(1, gpc.createProxyQueue.size());

        // Mimic the thread that works the queue to create the proxy
        CreateProxyRunnable runnable = gpc.createProxyQueue.take();
        ProxyManager pm = getProxyManager();
        runnable.run(pm);

        // The runnable should have put the actual registration in the holder
        ServiceReference<?> proxySR = holder.registration.getReference();
        for (String key : proxyProps.keySet()) {
            assertEquals(proxyProps.get(key), proxySR.getProperty(key));
        }

        // Check that the proxy registration was done on the original provider bundle's context
        EasyMock.verify(providerBC);

        // Test that the actual proxy invokes the original service...
        Object proxyService = serviceMap.get(proxySR);
        assertNotSame("The proxy should not be the same object as the original service", testService, proxyService);
        if (testService instanceof TestServiceAPI) {
            assertEquals("Doing it", ((TestServiceAPI) proxyService).doit());
        }
        if (testService instanceof TestObjectWithoutInterface) {
            if (!runningUnderCoverage) {
                assertEquals(-42L, ((TestObjectWithoutInterface) proxyService).compute(42L));
            }
        }

        gpc.close();
        EasyMock.verify(holder.registration); // checks that the unregister call was made
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

    private ServiceReference<?> mockServiceReference(Bundle providerBundle,
            final Dictionary<String, Object> serviceProps) {
        ServiceReference<?> sr = EasyMock.createMock(ServiceReference.class);

        EasyMock.expect(sr.getPropertyKeys()).andReturn(
                Collections.list(serviceProps.keys()).toArray(new String [] {})).anyTimes();
        EasyMock.expect(sr.getProperty(EasyMock.isA(String.class))).andAnswer(new IAnswer<Object>() {
            @Override
            public Object answer() throws Throwable {
                return serviceProps.get(EasyMock.getCurrentArguments()[0]);
            }
        }).anyTimes();
        if (providerBundle != null) {
            EasyMock.expect(sr.getBundle()).andReturn(providerBundle).anyTimes();
        }
        EasyMock.replay(sr);
        return sr;
    }

    public interface TestServiceAPI {
        public String doit();
    }

    public class TestService implements TestServiceAPI {
        @Override
        public String doit() {
            return "Doing it";
        }
    }

    public class TestObjectWithoutInterface {
        public long compute(long l) {
            return -l;
        }
    }

    public class CombinedTestService extends TestObjectWithoutInterface implements TestServiceAPI {
        @Override
        public String doit() {
            return "Doing it";
        }
    }

    private abstract class AbstractService implements TestServiceAPI {
        @Override
        public String doit() {
            return "Doing it";
        }
    }

    public class EmptyPublicTestService extends AbstractService {}

    public class DescendantTestService extends EmptyPublicTestService {}

    private class PrivateTestService implements TestServiceAPI {
        @Override
        public String doit() {
            return "Doing it";
        }
    }

    private class PrivateTestServiceNoDirectInterfaces extends PrivateTestService {}

    public final class FinalTestService extends AbstractService implements TestServiceAPI {}
}
