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
import static org.junit.Assert.assertNotNull;

import java.util.Collection;
import java.util.Collections;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import org.apache.karaf.service.guard.impl.GuardProxyCatalog.ProxyMapKey;
import org.easymock.EasyMock;
import org.easymock.IAnswer;
import org.junit.Test;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.Filter;
import org.osgi.framework.FrameworkUtil;
import org.osgi.framework.ServiceEvent;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.hooks.service.ListenerHook.ListenerInfo;

public class GuardingEventHookTest {
    @Test
    public void testEventHook() throws Exception {
        BundleContext bc = EasyMock.createMock(BundleContext.class);
        EasyMock.replay(bc);

        GuardProxyCatalog gpc = new GuardProxyCatalog(mockBundleContext(7));

        Filter serviceFilter = FrameworkUtil.createFilter("(foo=bar)");
        GuardingEventHook geh = new GuardingEventHook(bc, gpc, serviceFilter);

        Dictionary<String, Object> props0 = new Hashtable<String, Object>();
        props0.put(Constants.SERVICE_ID, 13L);
        ServiceReference<?> sref0 = mockServiceReference(props0);
        ServiceEvent se0 = new ServiceEvent(ServiceEvent.REGISTERED, sref0);

        BundleContext client1BC = mockBundleContext(123);
        Map<BundleContext, Collection<ListenerInfo>> listeners0 = new HashMap<BundleContext, Collection<ListenerInfo>>();
        listeners0.put(client1BC, Collections.<ListenerInfo>emptyList());
        assertEquals("Precondition", 0, gpc.proxyMap.size());
        geh.event(se0, listeners0);
        assertEquals("No proxy should have been created because the service doesn't match the filter", 0, gpc.proxyMap.size());

        Dictionary<String, Object> props = new Hashtable<String, Object>();
        props.put(Constants.SERVICE_ID, 887L);
        props.put("a", "b");
        props.put("foo", "bar");
        ServiceReference<?> sref = mockServiceReference(props);
        ServiceEvent se = new ServiceEvent(ServiceEvent.REGISTERED, sref);

        Map<BundleContext, Collection<ListenerInfo>> listeners = new HashMap<BundleContext, Collection<ListenerInfo>>();
        listeners.put(client1BC, Collections.<ListenerInfo>emptyList());

        geh.event(se, listeners);
        assertEquals(0, listeners.size());
        assertEquals("Proxy should have been created for this client", 1, gpc.proxyMap.size());
        assertEquals(sref, gpc.proxyMap.keySet().iterator().next().serviceReference);
        assertEquals(client1BC, gpc.proxyMap.keySet().iterator().next().clientBundleContext);

        props.put("a", "c"); // Will change the properties of sref
        Map<BundleContext, Collection<ListenerInfo>> listeners2 = new HashMap<BundleContext, Collection<ListenerInfo>>();
        BundleContext client2BC = mockBundleContext(11);
        listeners2.put(client2BC, Collections.<ListenerInfo>emptyList());
        listeners2.put(client1BC, Collections.<ListenerInfo>emptyList());
        geh.event(new ServiceEvent(ServiceEvent.MODIFIED, sref), listeners2);
        assertEquals("There should be an additional proxy for client 2", 2, gpc.proxyMap.size());
        assertNotNull(gpc.proxyMap.get(new ProxyMapKey(sref, client1BC)));
        assertNotNull(gpc.proxyMap.get(new ProxyMapKey(sref, client2BC)));

        Dictionary<String, Object> props2 = new Hashtable<String, Object>();
        props2.put(Constants.SERVICE_ID, 1L);
        props2.put("foo", "bar");
        ServiceReference<?> sref2 = mockServiceReference(props2);

        Map<BundleContext, Collection<ListenerInfo>> listeners3 = new HashMap<BundleContext, Collection<ListenerInfo>>();
        listeners3.put(client1BC, Collections.<ListenerInfo>emptyList());
        listeners3.put(client1BC, Collections.<ListenerInfo>emptyList()); // Should be ignored
        geh.event(new ServiceEvent(ServiceEvent.REGISTERED, sref2), listeners3);
        assertEquals("There should be an additional procy for client1 to the new service", 3, gpc.proxyMap.size());
        assertNotNull(gpc.proxyMap.get(new ProxyMapKey(sref, client1BC)));
        assertNotNull(gpc.proxyMap.get(new ProxyMapKey(sref, client2BC)));
        assertNotNull(gpc.proxyMap.get(new ProxyMapKey(sref2, client1BC)));
    }

    private BundleContext mockBundleContext(long id) throws Exception {
        Bundle bundle = EasyMock.createNiceMock(Bundle.class);
        EasyMock.expect(bundle.getBundleId()).andReturn(id).anyTimes();

        BundleContext bc = EasyMock.createNiceMock(BundleContext.class);
        EasyMock.expect(bc.getBundle()).andReturn(bundle).anyTimes();
        EasyMock.expect(bc.createFilter(EasyMock.isA(String.class))).andAnswer(new IAnswer<Filter>() {
            @Override
            public Filter answer() throws Throwable {
                return FrameworkUtil.createFilter((String) EasyMock.getCurrentArguments()[0]);
            }
        }).anyTimes();
        EasyMock.replay(bc);

        EasyMock.expect(bundle.getBundleContext()).andReturn(bc).anyTimes();
        EasyMock.replay(bundle);

        return bc;
    }

    private ServiceReference<?> mockServiceReference(final Dictionary<String, Object> props) {
        return mockServiceReference(props, Object.class);
    }

    @SuppressWarnings("unchecked")
    private <T> ServiceReference<T> mockServiceReference(Dictionary<String, Object> props, Class<T> cls) {
        return (ServiceReference<T>) mockServiceReference(null, props);
    }

    private ServiceReference<?> mockServiceReference(Bundle providerBundle,
            final Dictionary<String, Object> serviceProps) {
        ServiceReference<?> sr = EasyMock.createMock(ServiceReference.class);

        // Make sure the properties are 'live' in that if they change the reference changes too
        EasyMock.expect(sr.getPropertyKeys()).andAnswer(new IAnswer<String[]>() {
                @Override
                public String[] answer() throws Throwable {
                    return Collections.list(serviceProps.keys()).toArray(new String [] {});
                }
            }).anyTimes();
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
}
