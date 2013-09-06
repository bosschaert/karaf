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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Dictionary;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;

import org.apache.karaf.service.guard.impl.GuardingFindHook.MultiplexingServiceTracker;
import org.easymock.EasyMock;
import org.easymock.IAnswer;
import org.junit.Test;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.BundleEvent;
import org.osgi.framework.Constants;
import org.osgi.framework.Filter;
import org.osgi.framework.FrameworkUtil;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceListener;
import org.osgi.framework.ServiceReference;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;

public class GuardingFindHookTest {
    @SuppressWarnings("unchecked")
    @Test
    public void testFindHook() throws Exception {
        Dictionary<String, Object> config = new Hashtable<String, Object>();
        config.put("service.guard", "(|(moo=foo)(foo=*))");

        BundleContext hookBC = mockConfigAdminBundleContext(config);
        GuardProxyCatalog gpc = new GuardProxyCatalog(hookBC);

        Filter serviceFilter = FrameworkUtil.createFilter("(foo=*)");
        GuardingFindHook gfh = new GuardingFindHook(hookBC, gpc, serviceFilter);

        BundleContext clientBC = mockBundleContext(31L);

        Dictionary<String, Object> props = new Hashtable<String, Object>();
        props.put(Constants.SERVICE_ID, 16L);
        props.put("moo", "foo");
        ServiceReference<?> sref = mockServiceReference(props);

        Collection<ServiceReference<?>> refs = new ArrayList<ServiceReference<?>>();
        refs.add(sref);

        assertEquals("Precondition", 0, gpc.proxyMap.size());
        gfh.find(clientBC, null, null, true, refs);
        assertEquals("The service doesn't match the filter so should have no effect", 0, gpc.proxyMap.size());
        assertEquals("The service doesn't match the filter so should be presented to the client",
                Collections.singletonList(sref), refs);

        long service2ID = 17L;
        Dictionary<String, Object> props2 = new Hashtable<String, Object>();
        props2.put(Constants.SERVICE_ID, service2ID);
        props2.put("foo", new Object());
        ServiceReference<?> sref2 = mockServiceReference(props2);

        Collection<ServiceReference<?>> refs2 = new ArrayList<ServiceReference<?>>();
        refs2.add(sref2);

        gfh.find(clientBC, null, null, true, refs2);
        assertEquals("The service should be hidden from the client", 0, refs2.size());
        assertEquals("The service should have caused a proxy creation", 1, gpc.proxyMap.size());
        assertEquals("A proxy creation job should have been created", 1, gpc.createProxyQueue.size());
        assertEquals(sref2.getProperty(Constants.SERVICE_ID), gpc.proxyMap.keySet().iterator().next());

        Collection<ServiceReference<?>> refs3 = new ArrayList<ServiceReference<?>>();
        refs3.add(sref2);

        // Ensure that the hook bundle has nothing hidden
        gfh.find(hookBC, null, null, true, refs3);
        assertEquals("The service should not be hidden from the hook bundle", Collections.singletonList(sref2), refs3);
        assertEquals("No proxy creation caused in this case", 1, gpc.proxyMap.size());
        assertEquals("No change expected", sref2.getProperty(Constants.SERVICE_ID), gpc.proxyMap.keySet().iterator().next());

        // Ensure that the system bundle has nothing hidden
        gfh.find(mockBundleContext(0L), null, null, true, refs3);
        assertEquals("The service should not be hidden from the framework bundle", Collections.singletonList(sref2), refs3);
        assertEquals("No proxy creation caused in this case", 1, gpc.proxyMap.size());
        assertEquals("No change expected", sref2.getProperty(Constants.SERVICE_ID), gpc.proxyMap.keySet().iterator().next());

        // Ensure that if we ask for the same client again, it will not create another proxy
        gpc.createProxyQueue.clear(); // Manually empty the queue
        gfh.find(clientBC, null, null, true, refs3);
        assertEquals("The service should be hidden from the client", 0, refs3.size());
        assertEquals("There is already a proxy for this client, no need for an additional one", 1, gpc.proxyMap.size());
        assertEquals("No additional jobs should have been scheduled", 0, gpc.createProxyQueue.size());
        assertEquals("No change expected", sref2.getProperty(Constants.SERVICE_ID), gpc.proxyMap.keySet().iterator().next());

        Collection<ServiceReference<?>> refs4 = new ArrayList<ServiceReference<?>>();
        refs4.add(sref2);

        // another client should not get another proxy
        BundleContext client2BC = mockBundleContext(32768L);
        gfh.find(client2BC, null, null, true, refs4);
        assertEquals("The service should be hidden for this new client", 0, refs4.size());
        assertEquals("No proxy creation job should have been created", 0, gpc.createProxyQueue.size());
        assertEquals("No proxy creation caused in this case", 1, gpc.proxyMap.size());
        assertEquals("No change expected", sref2.getProperty(Constants.SERVICE_ID), gpc.proxyMap.keySet().iterator().next());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testFindHookProxyServices() throws Exception {
        Dictionary<String, Object> config = new Hashtable<String, Object>();
        config.put("service.guard", "(service.id=*)");

        BundleContext hookBC = mockConfigAdminBundleContext(config);
        GuardProxyCatalog gpc = new GuardProxyCatalog(hookBC);

        Filter serviceFilter = FrameworkUtil.createFilter("(service.id=*)"); // any service
        GuardingFindHook gfh = new GuardingFindHook(hookBC, gpc, serviceFilter);

        BundleContext clientBC = mockBundleContext(31L);

        Dictionary<String, Object> props = new Hashtable<String, Object>();
        props.put(Constants.SERVICE_ID, 16L);
        props.put(GuardProxyCatalog.PROXY_SERVICE_KEY, Boolean.TRUE);
        ServiceReference<?> sref = mockServiceReference(props);

        Collection<ServiceReference<?>> refs = new ArrayList<ServiceReference<?>>();
        refs.add(sref);
        gfh.find(clientBC, null, null, false, refs);
        assertEquals("No proxy should have been created for the proxy find", 0, gpc.proxyMap.size());
        assertEquals("As the proxy is for this bundle is should be visible and remain on the list",
                Collections.singletonList(sref), refs);
    }

    @Test
    public void testNullFilter() throws Exception {
        BundleContext hookBC = mockBundleContext(5L);
        GuardProxyCatalog gpc = new GuardProxyCatalog(hookBC);

        GuardingFindHook gfh = new GuardingFindHook(hookBC, gpc, null);
        gfh.find(null, null, null, true, null); // should just do nothing
    }

    @Test
    public void testBundleListener() {
        BundleContext bc = EasyMock.createMock(BundleContext.class);
        bc.addBundleListener(EasyMock.isA(GuardingFindHook.class));
        EasyMock.expectLastCall().once();
        EasyMock.replay(bc);

        GuardingFindHook gfh = new GuardingFindHook(bc, null, null);
        EasyMock.verify(bc);

        EasyMock.reset(bc);
        bc.removeBundleListener(gfh);
        EasyMock.replay(bc);

        gfh.close();
        EasyMock.verify(bc);
    }

    @Test
    public void testRoleBasedFind1() throws Exception {
        Filter nrf = nonRoleFilter("(&(test=val*)(" + GuardProxyCatalog.SERVICE_GUARD_ROLES_PROPERTY + "=myrole))");

        // Check that the filter created to find service that don't have the roles matches the right services
        assertTrue(nrf.match(dict("test=value")));
        assertTrue(nrf.match(dict("test=value2", "foo=bar")));
        assertFalse(nrf.match(dict("test=value", GuardProxyCatalog.SERVICE_GUARD_ROLES_PROPERTY + "=myrole", GuardProxyCatalog.PROXY_SERVICE_KEY + "=true")));
        assertFalse(nrf.match(dict("test=value", GuardProxyCatalog.SERVICE_GUARD_ROLES_PROPERTY + "=somerole", GuardProxyCatalog.PROXY_SERVICE_KEY + "=true")));
        assertFalse(nrf.match(dict("test=value", GuardProxyCatalog.SERVICE_GUARD_ROLES_PROPERTY + "=somerole",
                GuardProxyCatalog.SERVICE_GUARD_ROLES_PROPERTY + "=testrole", GuardProxyCatalog.PROXY_SERVICE_KEY + "=true")));
    }

    @Test
    public void testRoleBasedFind2() throws Exception {
        Filter nrf = nonRoleFilter("(&(|(" + GuardProxyCatalog.SERVICE_GUARD_ROLES_PROPERTY + "=myrole)"
                + "(" + GuardProxyCatalog.SERVICE_GUARD_ROLES_PROPERTY + "=myotherrole))(|(test.test=val*)(x>=6)))");

        // Check that the filter created to find service that don't have the roles matches the right services
        assertTrue(nrf.match(dict("test.test=value")));
        assertTrue(nrf.match(dict("x=7")));
        assertTrue(nrf.match(dict("test.test=value", "x=999")));
        assertTrue(nrf.match(dict("test.test=value", "x=5")));
        assertTrue(nrf.match(dict("test=value", "x=999")));
        assertFalse(nrf.match(dict("test=value", "x=5")));
        assertFalse(nrf.match(dict("test=value", "x=y", GuardProxyCatalog.SERVICE_GUARD_ROLES_PROPERTY + "=myrole", GuardProxyCatalog.PROXY_SERVICE_KEY + "=true")));
        assertFalse(nrf.match(dict("test=value", GuardProxyCatalog.SERVICE_GUARD_ROLES_PROPERTY + "=myotherrole", GuardProxyCatalog.PROXY_SERVICE_KEY + "=true")));
        assertFalse(nrf.match(dict("test=value", GuardProxyCatalog.SERVICE_GUARD_ROLES_PROPERTY + "=myrole", GuardProxyCatalog.PROXY_SERVICE_KEY + "=true",
                GuardProxyCatalog.SERVICE_GUARD_ROLES_PROPERTY + "=myotherrole")));
    }

    @Test
    public void testRoleBasedFind3() throws Exception {
        Filter nrf = nonRoleFilter("(&(a=b)(|(" + GuardProxyCatalog.SERVICE_GUARD_ROLES_PROPERTY + "=x)"
                + "(!(" + GuardProxyCatalog.SERVICE_GUARD_ROLES_PROPERTY + "=*))))");

        assertTrue(nrf.match(dict("a=b")));
    }

    @Test
    public void testRoleBasedFind4() throws Exception {
        Filter nrf = nonRoleFilter("(&(a=b)(! (" + GuardProxyCatalog.SERVICE_GUARD_ROLES_PROPERTY + "=* )))");

        assertTrue(nrf.match(dict("a=b")));
    }
    @Test
    public void testRoleBasedFindNotNeeded() throws Exception {
        List<Filter> filtersCreated = new ArrayList<Filter>();
        BundleContext hookBC = mockBundleContext(5L, filtersCreated);
        GuardProxyCatalog gpc = new GuardProxyCatalog(hookBC);

        Filter serviceFilter = FrameworkUtil.createFilter("(a=*)");
        GuardingFindHook gfh = new GuardingFindHook(hookBC, gpc, serviceFilter);

        BundleContext clientBC = mockBundleContext(98765L);
        filtersCreated.clear();
        gfh.find(clientBC, null, "(a=b)", true, Collections.<ServiceReference<?>>emptyList());
        assertEquals("The filter doesn't contain a role, so non-role filter should have been created", 0, filtersCreated.size());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testMultiplexingServiceTracker() throws Exception {
        // This test examines the lifecycle and behaviour of the MultiplexingServiceTracker
        Dictionary<String, Object> config = new Hashtable<String, Object>();
        config.put("service.guard", "(service.id=*)");

        BundleContext hookBC = mockConfigAdminBundleContext(config);
        GuardProxyCatalog gpc = new GuardProxyCatalog(hookBC);

        Filter serviceFilter = FrameworkUtil.createFilter("(a.b>=10)");
        GuardingFindHook gfh = new GuardingFindHook(hookBC, gpc, serviceFilter);

        String roleFilter = "(&(a.b=*)(" + GuardProxyCatalog.SERVICE_GUARD_ROLES_PROPERTY + "=myrole))";
        BundleContext clientBC = mockBundleContext(98765L);

        // Test that calling find with a condition on the roles property will create a service tracker
        // without that condition
        assertEquals(0, gfh.trackers.size());
        gfh.find(clientBC, null, roleFilter, true, Collections.<ServiceReference<?>>emptyList());
        assertEquals(0, gpc.proxyMap.size());
        assertEquals("Should have added a tracker", 1, gfh.trackers.size());
        String nonRoleFS = gfh.trackers.keySet().iterator().next();
        Filter nonRoleFilter = FrameworkUtil.createFilter(nonRoleFS);
        MultiplexingServiceTracker mst = gfh.trackers.get(nonRoleFS);
        assertEquals(Collections.singletonList(clientBC), mst.clientBCs);
        assertTrue(mst.getTrackingCount() >= 0);

        // Let another client find on the same condition, it should be added to the same MST
        BundleContext client2BC = mockBundleContext(32767L);

        long serviceID = 51L;
        Hashtable<String, Object> props = new Hashtable<String, Object>();
        props.put(Constants.SERVICE_ID, serviceID);
        props.put("a.b", 10);
        ServiceReference<?> sref = mockServiceReference(props);
        assertTrue("This service should match the filter without the roles piece", nonRoleFilter.match(sref));
        Collection<ServiceReference<?>> refs = new HashSet<ServiceReference<?>>(Arrays.<ServiceReference<?>>asList(sref));
        gfh.find(client2BC, null, roleFilter, true, refs);
        assertEquals(1, gpc.proxyMap.size());
        assertNotNull(gpc.proxyMap.get(serviceID));

        assertEquals("The additional client interest in the same filter should have added it to the list of interested bundles",
                2, mst.clientBCs.size());
        assertTrue(mst.clientBCs.contains(clientBC));
        assertTrue(mst.clientBCs.contains(client2BC));

        long service2ID = 52L;
        Hashtable<String, Object> props2 = new Hashtable<String, Object>();
        props2.put(Constants.SERVICE_ID, service2ID);
        props2.put("a.b", 10);
        ServiceReference<Object> sref2 = mockServiceReference(props2);
        mst.addingService(sref2);

        // Let the MST receive a callback of the new (matching) service. It should a new shared proxy for both clients
        assertEquals("Should have added a new proxy for the service", 2, gpc.proxyMap.size());
        Set<Long> expectedKeys = new HashSet<Long>(Arrays.asList(serviceID, service2ID));
        assertEquals(expectedKeys, gpc.proxyMap.keySet());

        // If the MST receives a callback that doesn't match the main proxifying filter it should have no effect
        Hashtable<String, Object> props3 = new Hashtable<String, Object>();
        props3.put(Constants.SERVICE_ID, 55L);
        props3.put("a.b", 5);
        ServiceReference<Object> sref3 = mockServiceReference(props3);
        mst.addingService(sref3);
        assertEquals("There should not be any new proxies, as the reference passed in doesn't match the main filter",
                expectedKeys, gpc.proxyMap.keySet());

        // A new service lookup with a condition on the roles should add an extra MST
        String roleFilter2 = "(" + GuardProxyCatalog.SERVICE_GUARD_ROLES_PROPERTY + "=myotherrole)";
        gfh.find(clientBC, null, roleFilter2, true, Collections.<ServiceReference<?>>emptySet());
        assertEquals("Amount of proxies services should still be the same", expectedKeys, gpc.proxyMap.keySet());
        assertEquals("There should now be an additional tracker", 2, gfh.trackers.size());

        MultiplexingServiceTracker mst2 = null;
        for (MultiplexingServiceTracker m : gfh.trackers.values()) {
            if (m != mst) {
                mst2 = m;
            }
        }
        assertEquals(Collections.singletonList(clientBC), mst2.clientBCs);
        HashSet<String> expectedFilters = new HashSet<String>(gfh.trackers.keySet());

        gfh.bundleChanged(new BundleEvent(BundleEvent.STOPPED, client2BC.getBundle()));
        assertEquals(expectedFilters, gfh.trackers.keySet());
        for (MultiplexingServiceTracker m : gfh.trackers.values()) {
            assertEquals("Only one bundle should be tracked by this MST", 1, m.clientBCs.size());
            assertTrue("Should still be open", m.getTrackingCount() >= 0);
        }

        // The started event should have no effect
        gfh.bundleChanged(new BundleEvent(BundleEvent.STARTED, clientBC.getBundle()));
        assertEquals(expectedFilters, gfh.trackers.keySet());
        for (MultiplexingServiceTracker m : gfh.trackers.values()) {
            assertEquals("Only one bundle should be tracked by this MST", 1, m.clientBCs.size());
            assertTrue("Should still be open", m.getTrackingCount() >= 0);
        }

        gfh.bundleChanged(new BundleEvent(BundleEvent.STOPPED, clientBC.getBundle()));
        assertEquals("Tracker should be closed", -1, mst.getTrackingCount());
        assertEquals("Tracker should be closed", -1, mst2.getTrackingCount());
        assertEquals("No trackers should be left", 0, gfh.trackers.size());
    }

    @Test
    public void testMultiplexingServiceTracker2() throws Exception {
        BundleContext hookBC = mockBundleContext(11);
        GuardProxyCatalog gpc = new GuardProxyCatalog(hookBC);
        GuardingFindHook gfh = new GuardingFindHook(hookBC, gpc, FrameworkUtil.createFilter("(a.b>=10)"));

        BundleContext clientBC = mockBundleContext(11);
        MultiplexingServiceTracker mst = gfh.new MultiplexingServiceTracker(hookBC, clientBC, "(a=b)");
        assertEquals(Collections.singletonList(clientBC), mst.clientBCs);

        mst.addBundleContext(mockBundleContext(0));
        assertEquals("Should not track the system bundle", Collections.singletonList(clientBC), mst.clientBCs);

        mst.addBundleContext(hookBC);
        assertEquals("Should not track the hook bundle itself", Collections.singletonList(clientBC), mst.clientBCs);
    }

    private Filter nonRoleFilter(String roleFilter) throws Exception, InvalidSyntaxException {
        List<Filter> filtersCreated = new ArrayList<Filter>();
        BundleContext hookBC = mockBundleContext(5L, filtersCreated);
        GuardProxyCatalog gpc = new GuardProxyCatalog(hookBC);

        Filter serviceFilter = FrameworkUtil.createFilter("(x=y)"); // doesn't matter here
        GuardingFindHook gfh = new GuardingFindHook(hookBC, gpc, serviceFilter);

        BundleContext clientBC = mockBundleContext(98765L);

        filtersCreated.clear();
        gfh.find(clientBC, null, roleFilter, true, Collections.<ServiceReference<?>>emptyList());
        assertEquals("Only one filter expected to be created", 1, filtersCreated.size());
        Filter nonRoleFilter = filtersCreated.get(0);
        return nonRoleFilter;
    }

    private Dictionary<String, Object> dict(String ... entry) {
        Dictionary<String, Object> d = new Hashtable<String, Object>();
        for (String e : entry) {
            int idx = e.indexOf('=');
            if (idx < 0) {
                throw new IllegalArgumentException(e);
            }
            d.put(e.substring(0, idx), e.substring(idx + 1));
        }
        return d;
    }

    private BundleContext mockBundleContext(long id) throws Exception {
        return mockBundleContext(id, new ArrayList<Filter>());
    }

    private BundleContext mockBundleContext(long id, final List<Filter> filtersCreated) throws Exception {
        Bundle bundle = EasyMock.createNiceMock(Bundle.class);
        EasyMock.expect(bundle.getBundleId()).andReturn(id).anyTimes();

        BundleContext bc = EasyMock.createNiceMock(BundleContext.class);
        EasyMock.expect(bc.getBundle()).andReturn(bundle).anyTimes();
        EasyMock.expect(bc.createFilter(EasyMock.isA(String.class))).andAnswer(new IAnswer<Filter>() {
            @Override
            public Filter answer() throws Throwable {
                Filter filter = FrameworkUtil.createFilter((String) EasyMock.getCurrentArguments()[0]);
                filtersCreated.add(filter);
                return filter;
            }
        }).anyTimes();
        EasyMock.replay(bc);

        EasyMock.expect(bundle.getBundleContext()).andReturn(bc).anyTimes();
        EasyMock.replay(bundle);

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
        EasyMock.expect(ca.listConfigurations("(&(service.pid=org.apache.karaf.service.acl.*)(service.guard=*))")).andReturn(configurations).anyTimes();
        EasyMock.replay(ca);

        final ServiceReference caSR = EasyMock.createMock(ServiceReference.class);
        EasyMock.replay(caSR);

        Bundle b = EasyMock.createMock(Bundle.class);
        EasyMock.expect(b.getBundleId()).andReturn(877342449L).anyTimes();
        EasyMock.replay(b);

        BundleContext bc = EasyMock.createNiceMock(BundleContext.class);
        EasyMock.expect(bc.getBundle()).andReturn(b).anyTimes();
        EasyMock.expect(bc.createFilter(EasyMock.isA(String.class))).andAnswer(new IAnswer<Filter>() {
            @Override
            public Filter answer() throws Throwable {
                return FrameworkUtil.createFilter((String) EasyMock.getCurrentArguments()[0]);
            }
        }).anyTimes();
        String cmFilter = "(&(objectClass=" + ConfigurationAdmin.class.getName() + ")"
                + "(!(" + GuardProxyCatalog.PROXY_SERVICE_KEY + "=*)))";
        bc.addServiceListener(EasyMock.isA(ServiceListener.class), EasyMock.eq(cmFilter));
        EasyMock.expectLastCall().anyTimes();
        EasyMock.expect(bc.getServiceReferences(EasyMock.anyObject(String.class), EasyMock.eq(cmFilter))).
        andReturn(new ServiceReference<?> [] {caSR}).anyTimes();
        EasyMock.expect(bc.getService(caSR)).andReturn(ca).anyTimes();
        EasyMock.replay(bc);
        return bc;
    }

    private ServiceReference<Object> mockServiceReference(final Dictionary<String, Object> props) {
        @SuppressWarnings("unchecked")
        ServiceReference<Object> sr = EasyMock.createMock(ServiceReference.class);

        // Make sure the properties are 'live' in that if they change the reference changes too
        EasyMock.expect(sr.getPropertyKeys()).andAnswer(new IAnswer<String[]>() {
                @Override
                public String[] answer() throws Throwable {
                    return Collections.list(props.keys()).toArray(new String [] {});
                }
            }).anyTimes();
        EasyMock.expect(sr.getProperty(EasyMock.isA(String.class))).andAnswer(new IAnswer<Object>() {
            @Override
            public Object answer() throws Throwable {
                return props.get(EasyMock.getCurrentArguments()[0]);
            }
        }).anyTimes();
        EasyMock.replay(sr);
        return sr;
    }
}
