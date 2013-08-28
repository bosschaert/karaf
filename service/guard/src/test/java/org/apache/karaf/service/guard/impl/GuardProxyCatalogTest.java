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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.PrivilegedAction;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.security.auth.Subject;

import org.apache.aries.proxy.ProxyManager;
import org.apache.aries.proxy.impl.AsmProxyManager;
import org.apache.karaf.jaas.boot.principal.RolePrincipal;
import org.easymock.EasyMock;
import org.easymock.IAnswer;
import org.junit.Test;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.Filter;
import org.osgi.framework.FrameworkUtil;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceEvent;
import org.osgi.framework.ServiceListener;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.ServiceRegistration;
import org.osgi.framework.wiring.BundleWiring;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;

public class GuardProxyCatalogTest {
    // Some assertions fail when run under a code coverage tool, they are skipped when this is set to true
    private static final boolean runningUnderCoverage = false; // set to false before committing any changes

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

        testCreateProxy(TestServiceAPI.class, new TestService());
        testCreateProxy(TestServiceAPI.class, new DescendantTestService());
        testCreateProxy(TestServiceAPI.class, new PrivateTestService());
        testCreateProxy(TestServiceAPI.class, new PrivateTestServiceNoDirectInterfaces());
        testCreateProxy(TestServiceAPI.class, new FinalTestService());
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

    @Test
    public void testDontReProxy() throws Exception {
        BundleContext bc = mockBundleContext();

        GuardProxyCatalog gpc = new GuardProxyCatalog(bc);
        assertEquals("Precondition", 0, gpc.proxyMap.size());

        Dictionary<String, Object> props = new Hashtable<String, Object>();
        props.put(GuardProxyCatalog.PROXY_MARKER_KEY, 123l);
        ServiceReference<?> sr = mockServiceReference(props);

        BundleContext clientBC = EasyMock.createMock(BundleContext.class);
        EasyMock.replay(clientBC);

        gpc.proxyIfNotAlreadyProxied(sr, clientBC);
        assertEquals(0, gpc.proxyMap.size());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testAssignRoles() throws Exception {
        Dictionary<String, Object> config = new Hashtable<String, Object>();
        config.put(Constants.SERVICE_PID, "foobar");
        config.put("service.guard", "(objectClass=" + TestServiceAPI.class.getName() + ")");
        config.put("somemethod", "a,b");
        config.put("someOtherMethod(int)", "c");
        config.put("someOtherMethod(int)[/12/]", "d");
        config.put("someOtherMethod(int)[\"42\"]", "e");
        config.put("someFoo*", "f");

        BundleContext bc = mockConfigAdminBundleContext(config);

        Dictionary<String, Object> proxyProps = testCreateProxy(bc, TestServiceAPI.class, new TestService());
        assertEquals(new HashSet<String>(Arrays.asList("a", "b", "c", "d", "e", "f")),
                new HashSet<String>((Collection<String>) proxyProps.get(GuardProxyCatalog.SERVICE_GUARD_ROLES_PROPERTY)));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testInvocationBlocking1() throws Exception {
        Dictionary<String, Object> c1 = new Hashtable<String, Object>();
        c1.put(Constants.SERVICE_PID, "foobar");
        c1.put("service.guard", "(objectClass=" + TestServiceAPI.class.getName() + ")");
        c1.put("doit", "a,b");
        Dictionary<String, Object> c2 = new Hashtable<String, Object>();
        c2.put(Constants.SERVICE_PID, "barfoobar");
        c2.put("service.guard", "(objectClass=" + TestObjectWithoutInterface.class.getName() + ")");
        c2.put("compute", "c");

        BundleContext bc = mockConfigAdminBundleContext(c1, c2);

        final Object proxy = testCreateProxy(bc, new Class [] {TestServiceAPI.class, TestObjectWithoutInterface.class}, new CombinedTestService());

        // Run with the right credentials so we can test the expected roles
        Subject subject = new Subject();
        subject.getPrincipals().add(new RolePrincipal("b"));
        Subject.doAs(subject, new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                assertEquals("Doing it", ((TestServiceAPI) proxy).doit());
                if (!runningUnderCoverage) {
                    try {
                        ((TestObjectWithoutInterface) proxy).compute(44L);
                        fail("Should have been blocked");
                    } catch (SecurityException se) {
                        // good
                    }
                }

                return null;
            }
        });
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testInvocationBlocking2() throws Exception {
        Dictionary<String, Object> config = new Hashtable<String, Object>();
        config.put(Constants.SERVICE_PID, "barfoobar");
        config.put("service.guard", "(objectClass=" + TestObjectWithoutInterface.class.getName() + ")");
        config.put("compute(long)[\"42\"]", "b");
        config.put("compute(long)", "c");

        BundleContext bc = mockConfigAdminBundleContext(config);

        final Object proxy = testCreateProxy(bc, new Class [] {TestServiceAPI.class, TestObjectWithoutInterface.class}, new CombinedTestService());

        // Run with the right credentials so we can test the expected roles
        Subject subject = new Subject();
        subject.getPrincipals().add(new RolePrincipal("b"));
        Subject.doAs(subject, new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                if (!runningUnderCoverage) {
                    assertEquals(-42L, ((TestObjectWithoutInterface) proxy).compute(42L));
                    try {
                        ((TestObjectWithoutInterface) proxy).compute(44L);
                        fail("Should have been blocked");
                    } catch (SecurityException se) {
                        // good
                    }
                }

                return null;
            }
        });
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testInvocationBlocking3() throws Exception {
        class MyService implements TestServiceAPI, TestServiceAPI2 {
            public String doit(String s) {
                return new StringBuilder(s).reverse().toString();
            }

            public String doit() {
                return "Doing it";
            }
        };

        Dictionary<String, Object> c1 = new Hashtable<String, Object>();
        c1.put(Constants.SERVICE_PID, "foobar");
        c1.put("service.guard", "(objectClass=" + TestServiceAPI.class.getName() + ")");
        c1.put("do*", "c");
        Dictionary<String, Object> c2 = new Hashtable<String, Object>();
        c2.put(Constants.SERVICE_PID, "foobar2");
        c2.put("service.guard", "(objectClass=" + TestServiceAPI2.class.getName() + ")");
        c2.put("doit(java.lang.String)[/[tT][a]+/]", "b,d # a regex rule");
        c2.put("doit(java.lang.String)", "a");

        BundleContext bc = mockConfigAdminBundleContext(c1, c2);

        final Object proxy = testCreateProxy(bc, new Class [] {TestServiceAPI.class, TestServiceAPI2.class}, new MyService());

        // Run with the right credentials so we can test the expected roles
        Subject subject = new Subject();
        subject.getPrincipals().add(new RolePrincipal("c"));
        Subject.doAs(subject, new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                assertEquals("Doing it", ((TestServiceAPI) proxy).doit());
                return null;
            }
        });

        Subject subject2 = new Subject();
        subject2.getPrincipals().add(new RolePrincipal("b"));
        subject2.getPrincipals().add(new RolePrincipal("f"));
        Subject.doAs(subject2, new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                try {
                    assertEquals("Doing it", ((TestServiceAPI) proxy).doit());
                    fail("Should have been blocked");
                } catch (SecurityException se) {
                    // good
                }
                assertEquals("aaT", ((TestServiceAPI2) proxy).doit("Taa"));
                try {
                    ((TestServiceAPI2) proxy).doit("t");
                    fail("Should have been blocked");
                } catch (SecurityException se) {
                    // good
                }
                return null;
            }
        });
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testInvocationBlocking4() throws Exception {
        BundleContext bc = mockConfigAdminBundleContext();

        final Object proxy = testCreateProxy(bc, new Class [] {TestServiceAPI.class, TestObjectWithoutInterface.class}, new CombinedTestService());

        // Run with the right credentials so we can test the expected roles
        Subject subject = new Subject();
        subject.getPrincipals().add(new RolePrincipal("b"));
        Subject.doAs(subject, new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                assertEquals("Doing it", ((TestServiceAPI) proxy).doit());
                if (!runningUnderCoverage) {
                    assertEquals(42L, ((TestObjectWithoutInterface) proxy).compute(-42L));
                    assertEquals(-44L, ((TestObjectWithoutInterface) proxy).compute(44L));
                }

                return null;
            }
        });
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    @Test
    public void testProxyCreationThread() throws Exception {
        ProxyManager proxyManager = getProxyManager();

        ServiceReference pmSref = EasyMock.createMock(ServiceReference.class);
        EasyMock.replay(pmSref);
        ServiceReference pmSref2 = EasyMock.createMock(ServiceReference.class);
        EasyMock.replay(pmSref2);

        BundleContext bc = EasyMock.createNiceMock(BundleContext.class);
        EasyMock.expect(bc.createFilter(EasyMock.isA(String.class))).andAnswer(new IAnswer<Filter>() {
            @Override
            public Filter answer() throws Throwable {
                return FrameworkUtil.createFilter((String) EasyMock.getCurrentArguments()[0]);
            }
        }).anyTimes();
        final ServiceListener [] pmListenerHolder = new ServiceListener [1];
        String pmFilter = "(&(objectClass=org.apache.aries.proxy.ProxyManager)(!(.org.apache.karaf.service.guard.impl.GuardProxyCatalog=*)))";
        bc.addServiceListener(EasyMock.isA(ServiceListener.class), EasyMock.eq(pmFilter));
        EasyMock.expectLastCall().andAnswer(new IAnswer<Object>() {
            @Override
            public Object answer() throws Throwable {
                pmListenerHolder[0] = (ServiceListener) EasyMock.getCurrentArguments()[0];
                return null;
            }
        }).anyTimes();
        EasyMock.expect(bc.getService(pmSref)).andReturn(proxyManager).anyTimes();
        EasyMock.expect(bc.getService(pmSref2)).andReturn(proxyManager).anyTimes();
        EasyMock.replay(bc);

        // This should put a ServiceListener in the pmListenerHolder, the ServiceTracker does that
        GuardProxyCatalog gpc = new GuardProxyCatalog(bc);

        // The service being proxied has these properties
        final Hashtable<String, Object> serviceProps = new Hashtable<String, Object>();
        serviceProps.put(Constants.OBJECTCLASS, new String [] {TestServiceAPI.class.getName()});

        final Map<ServiceReference<?>, Object> serviceMap = new HashMap<ServiceReference<?>, Object>();

        // The mock bundle context for the bundle providing the service is set up here
        BundleContext providerBC = EasyMock.createMock(BundleContext.class);
        // These are the expected service properties of the proxy registration. Note the proxy marker...
        final Hashtable<String, Object> expectedProxyProps = new Hashtable<String, Object>(serviceProps);
        expectedProxyProps.put(GuardProxyCatalog.PROXY_MARKER_KEY, 999L);
        EasyMock.expect(providerBC.registerService(
                EasyMock.isA(String[].class),
                EasyMock.anyObject(),
                EasyMock.isA(Dictionary.class))).andAnswer(new IAnswer() {
                    @Override
                    public ServiceRegistration answer() throws Throwable {
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
        EasyMock.expect(clientBundle.loadClass(TestServiceAPI.class.getName())).andReturn((Class) TestServiceAPI.class).anyTimes();
        EasyMock.replay(clientBundle);

        // The mock bundle context for the client bundle
        BundleContext clientBC = EasyMock.createMock(BundleContext.class);
        EasyMock.expect(clientBC.getBundle()).andReturn(clientBundle).anyTimes();
        EasyMock.expect(clientBC.getService(sr)).andReturn(new TestService()).anyTimes();
        EasyMock.replay(clientBC);

        assertEquals("Precondition", 0, gpc.proxyMap.size());
        assertEquals("Precondition", 0, gpc.createProxyQueue.size());
        // Create the proxy for the service
        gpc.proxyIfNotAlreadyProxied(sr, clientBC);
        assertEquals(1, gpc.proxyMap.size());
        assertEquals(1, gpc.createProxyQueue.size());

        // The actual proxy creation is done asynchronously.
        GuardProxyCatalog.ServiceRegistrationHolder holder = gpc.proxyMap.get(new GuardProxyCatalog.ProxyMapKey(sr, clientBC));
        assertNull("The registration shouldn't have happened yet", holder.registration);
        assertEquals(1, gpc.createProxyQueue.size());

        Thread[] tarray = new Thread[Thread.activeCount()];
        Thread.enumerate(tarray);
        for (Thread t : tarray) {
            if (t != null) {
                assertTrue(!GuardProxyCatalog.PROXY_CREATOR_THREAD_NAME.equals(t.getName()));
            }
        }

        // make the proxy manager appear
        pmListenerHolder[0].serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, pmSref));
        Thread.sleep(400); // give the system some time to send the events...

        Thread ourThread = null;
        Thread[] tarray2 = new Thread[Thread.activeCount()];
        Thread.enumerate(tarray2);
        for (Thread t : tarray2) {
            if (t != null) {
                if (t.getName().equals(GuardProxyCatalog.PROXY_CREATOR_THREAD_NAME)) {
                    ourThread = t;
                }
            }
        }
        assertNotNull(ourThread);
        assertTrue(ourThread.isDaemon());
        assertTrue(ourThread.isAlive());
        assertNotNull(holder.registration);

        assertEquals(0, gpc.createProxyQueue.size());

        int numProxyThreads = 0;
        pmListenerHolder[0].serviceChanged(new ServiceEvent(ServiceEvent.REGISTERED, pmSref2));
        Thread.sleep(300); // give the system some time to send the events...

        Thread[] tarray3 = new Thread[Thread.activeCount()];
        Thread.enumerate(tarray3);
        for (Thread t : tarray3) {
            if (t != null) {
                if (t.getName().equals(GuardProxyCatalog.PROXY_CREATOR_THREAD_NAME)) {
                    numProxyThreads++;
                }
            }
        }
        assertEquals("Maximum 1 proxy thread, even if there is more than 1 proxy service", 1, numProxyThreads);

        // Clean up thread
        pmListenerHolder[0].serviceChanged(new ServiceEvent(ServiceEvent.UNREGISTERING, pmSref));
        Thread.sleep(300); // Give the system some time to stop the threads...
        Thread[] tarray4 = new Thread[Thread.activeCount()];
        Thread.enumerate(tarray4);
        for (Thread t : tarray4) {
            if (t != null) {
                assertTrue(!GuardProxyCatalog.PROXY_CREATOR_THREAD_NAME.equals(t.getName()));
            }
        }
    }

    public Dictionary<String, Object> testCreateProxy(Class<?> intf, Object testService) throws Exception {
        return testCreateProxy(mockBundleContext(), intf, intf, testService);
    }

    public Dictionary<String, Object> testCreateProxy(BundleContext bc, Class<?> intf, Object testService) throws Exception {
        return testCreateProxy(bc, intf, intf, testService);
    }

    public Dictionary<String, Object> testCreateProxy(Class<?> intf, Class<?> proxyRegClass, Object testService) throws Exception {
        return testCreateProxy(mockBundleContext(), intf, proxyRegClass, testService);
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    public Dictionary<String, Object> testCreateProxy(BundleContext bc, Class intf, final Class proxyRegClass, Object testService) throws Exception {
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
        final Hashtable<String, Object> expectedProxyProps = new Hashtable<String, Object>(serviceProps);
        expectedProxyProps.put(GuardProxyCatalog.PROXY_MARKER_KEY, 999L);
        // This will check that the right proxy is being registered.
        EasyMock.expect(providerBC.registerService(
                EasyMock.isA(String[].class),
                EasyMock.anyObject(),
                EasyMock.isA(Dictionary.class))).andAnswer(new IAnswer() {
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
                        for (String key : expectedProxyProps.keySet()) {
                            assertEquals(expectedProxyProps.get(key), props.get(key));
                        }

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
        GuardProxyCatalog.CreateProxyRunnable runnable = gpc.createProxyQueue.take();
        ProxyManager pm = getProxyManager();
        runnable.run(pm);

        // The runnable should have put the actual registration in the holder
        ServiceReference<?> proxySR = holder.registration.getReference();
        for (String key : expectedProxyProps.keySet()) {
            assertEquals(expectedProxyProps.get(key), proxySR.getProperty(key));
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

        // Attempt to proxy the service again, make sure that no re-proxying happens
        assertEquals("Precondition", 1, gpc.proxyMap.size());
        assertEquals("Precondition", 0, gpc.createProxyQueue.size());
        gpc.proxyIfNotAlreadyProxied(sr, clientBC);
        assertEquals("No additional proxy should have been created", 1, gpc.proxyMap.size());
        assertEquals("No additional work on the queue is expected", 0, gpc.createProxyQueue.size());

        Dictionary<String, Object> proxyProps = getServiceReferenceProperties(proxySR);

        gpc.close();
        EasyMock.verify(holder.registration); // checks that the unregister call was made

        return proxyProps;
    }

    public Object testCreateProxy(Class<?> [] objectClasses, Object testService) throws Exception {
        return testCreateProxy(mockBundleContext(), objectClasses, objectClasses, testService);
    }

    public Object testCreateProxy(BundleContext bc, Class<?> [] objectClasses, Object testService) throws Exception {
        return testCreateProxy(bc, objectClasses, objectClasses, testService);
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    public Object testCreateProxy(BundleContext bc, Class [] objectClasses, final Class [] proxyRegClasses, Object testService) throws Exception {
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

        // Create the object that is actually being tested here
        GuardProxyCatalog gpc = new GuardProxyCatalog(bc);

        // The service being proxied has these properties
        final Hashtable<String, Object> serviceProps = new Hashtable<String, Object>();
        serviceProps.put(Constants.OBJECTCLASS, objClsMap.keySet().toArray(new String [] {}));
        serviceProps.put("bar", "foo");

        final Map<ServiceReference<?>, Object> serviceMap = new HashMap<ServiceReference<?>, Object>();

        // The mock bundle context for the bundle providing the service is set up here
        BundleContext providerBC = EasyMock.createMock(BundleContext.class);
        // These are the expected service properties of the proxy registration. Note the proxy marker...
        final Hashtable<String, Object> expectedProxyProps = new Hashtable<String, Object>(serviceProps);
        expectedProxyProps.put(GuardProxyCatalog.PROXY_MARKER_KEY, 999L);
        // This will check that the right proxy is being registered.
        EasyMock.expect(providerBC.registerService(
                EasyMock.isA(String[].class),
                EasyMock.anyObject(),
                EasyMock.isA(Dictionary.class))).andAnswer(new IAnswer() {
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
                        for (String key : expectedProxyProps.keySet()) {
                            assertEquals(expectedProxyProps.get(key), props.get(key));
                        }

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
        GuardProxyCatalog.CreateProxyRunnable runnable = gpc.createProxyQueue.take();
        ProxyManager pm = getProxyManager();
        runnable.run(pm);

        // The runnable should have put the actual registration in the holder
        ServiceReference<?> proxySR = holder.registration.getReference();
        for (String key : expectedProxyProps.keySet()) {
            assertEquals(expectedProxyProps.get(key), proxySR.getProperty(key));
        }

        // Check that the proxy registration was done on the original provider bundle's context
        EasyMock.verify(providerBC);

        // Test that the actual proxy invokes the original service...
        Object proxyService = serviceMap.get(proxySR);
        assertNotSame("The proxy should not be the same object as the original service", testService, proxyService);

        return proxyService;
    }

    private ProxyManager getProxyManager() {
        return new AsmProxyManager();
    }

    private Dictionary<String, Object> getServiceReferenceProperties(ServiceReference<?> sr) {
        Dictionary<String, Object> dict = new Hashtable<String, Object>();

        for (String key : sr.getPropertyKeys()) {
            dict.put(key, sr.getProperty(key));
        }

        return dict;
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

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private BundleContext mockConfigAdminBundleContext(Dictionary<String, Object> ... configs) throws IOException,
            InvalidSyntaxException {

        Configuration [] configurations = new Configuration[configs.length];

        for (int i = 0; i < configs.length; i++) {
            Configuration conf = EasyMock.createMock(Configuration.class);
            EasyMock.expect(conf.getProperties()).andReturn(configs[i]).anyTimes();
            EasyMock.expect(conf.getPid()).andReturn((String) configs[i].get(Constants.SERVICE_PID)).anyTimes();
            EasyMock.replay(conf);
            configurations[i] = conf;
        }

        ConfigurationAdmin ca = EasyMock.createMock(ConfigurationAdmin.class);
        EasyMock.expect(ca.listConfigurations("(service.guard=*)")).andReturn(configurations).anyTimes();
        EasyMock.replay(ca);

        final ServiceReference caSR = EasyMock.createMock(ServiceReference.class);
        EasyMock.replay(caSR);

        BundleContext bc = EasyMock.createNiceMock(BundleContext.class);
        EasyMock.expect(bc.createFilter(EasyMock.isA(String.class))).andAnswer(new IAnswer<Filter>() {
            @Override
            public Filter answer() throws Throwable {
                return FrameworkUtil.createFilter((String) EasyMock.getCurrentArguments()[0]);
            }
        }).anyTimes();
        String cmFilter = "(&(objectClass=org.osgi.service.cm.ConfigurationAdmin)(!(.org.apache.karaf.service.guard.impl.GuardProxyCatalog=*)))";
        bc.addServiceListener(EasyMock.isA(ServiceListener.class), EasyMock.eq(cmFilter));
        EasyMock.expectLastCall().anyTimes();
        EasyMock.expect(bc.getServiceReferences(EasyMock.anyObject(String.class), EasyMock.eq(cmFilter))).
            andReturn(new ServiceReference<?> [] {caSR}).anyTimes();
        EasyMock.expect(bc.getService(caSR)).andReturn(ca).anyTimes();
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
        String doit();
    }

    public class TestService implements TestServiceAPI {
        @Override
        public String doit() {
            return "Doing it";
        }
    }

    public interface TestServiceAPI2 {
        String doit(String s);
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
