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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Dictionary;
import java.util.Hashtable;

import org.easymock.EasyMock;
import org.easymock.IAnswer;
import org.junit.Test;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.Filter;
import org.osgi.framework.FrameworkUtil;
import org.osgi.framework.ServiceReference;

public class GuardingFindHookTest {
    @Test
    public void testFindHook() throws Exception {
        BundleContext hookBC = mockBundleContext(5L);
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

        Dictionary<String, Object> props2 = new Hashtable<String, Object>();
        props2.put(Constants.SERVICE_ID, 17L);
        props2.put("foo", new Object());
        ServiceReference<?> sref2 = mockServiceReference(props2);

        Collection<ServiceReference<?>> refs2 = new ArrayList<ServiceReference<?>>();
        refs2.add(sref2);

        gfh.find(clientBC, null, null, true, refs2);
        assertEquals("The service should be hidden from the client", 0, refs2.size());
        assertEquals("Precondition", 1, gpc.proxyMap.size());
        assertEquals(clientBC, gpc.proxyMap.keySet().iterator().next().clientBundleContext);
        assertEquals(sref2, gpc.proxyMap.keySet().iterator().next().serviceReference);
    }

    @Test
    public void testFindHookProxyServices() throws Exception {
        BundleContext hookBC = mockBundleContext(5L);
        GuardProxyCatalog gpc = new GuardProxyCatalog(hookBC);

        Filter serviceFilter = FrameworkUtil.createFilter("(service.id=*)"); // any service
        GuardingFindHook gfh = new GuardingFindHook(hookBC, gpc, serviceFilter);

        BundleContext clientBC = mockBundleContext(31L);

        Dictionary<String, Object> props = new Hashtable<String, Object>();
        props.put(Constants.SERVICE_ID, 16L);
        props.put(GuardProxyCatalog.PROXY_FOR_BUNDLE_KEY, 12L);
        props.put(GuardProxyCatalog.PROXY_FOR_SERVICE_KEY, 1L);
        ServiceReference<?> sref = mockServiceReference(props);

        Collection<ServiceReference<?>> refs = new ArrayList<ServiceReference<?>>();
        refs.add(sref);

        assertEquals("Precondition", 0, gpc.proxyMap.size());
        gfh.find(clientBC, null, null, false, refs);
        assertEquals("No proxy should have been created for the proxy find", 0, gpc.proxyMap.size());
        assertEquals("The proxy for a different bundle should have been hidden from the client", 0, refs.size());

        Dictionary<String, Object> props2 = new Hashtable<String, Object>();
        props2.put(Constants.SERVICE_ID, 16L);
        props2.put(GuardProxyCatalog.PROXY_FOR_BUNDLE_KEY, clientBC.getBundle().getBundleId());
        props2.put(GuardProxyCatalog.PROXY_FOR_SERVICE_KEY, 1L);
        ServiceReference<?> sref2 = mockServiceReference(props2);

        Collection<ServiceReference<?>> refs2 = new ArrayList<ServiceReference<?>>();
        refs2.add(sref2);
        gfh.find(clientBC, null, null, false, refs2);
        assertEquals("No proxy should have been created for the proxy find", 0, gpc.proxyMap.size());
        assertEquals("As the proxy is for this bundle is should be visible and remain on the list",
                Collections.singletonList(sref2), refs2);
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
        ServiceReference<?> sr = EasyMock.createMock(ServiceReference.class);

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
        if (null != null) {
            EasyMock.expect(sr.getBundle()).andReturn(null).anyTimes();
        }
        EasyMock.replay(sr);
        return sr;
    }
}
