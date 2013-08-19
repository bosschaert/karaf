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

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Dictionary;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.aries.proxy.InvocationListener;
import org.apache.aries.proxy.ProxyManager;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.Filter;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.cm.ConfigurationAdmin;
import org.osgi.util.tracker.ServiceTracker;

public class GuardProxyCatalog {
    private static final String PROXY_MARKER_KEY = "." + GuardProxyCatalog.class.getName();

    private final ServiceTracker<ConfigurationAdmin, ConfigurationAdmin> configAdminTracker;
    private final ServiceTracker<ProxyManager, ProxyManager> proxyManagerTracker;
    private final ConcurrentMap<ServiceReference<?>, ServiceRegistrationHolder> proxyMap =
            new ConcurrentHashMap<ServiceReference<?>, ServiceRegistrationHolder>();


    GuardProxyCatalog(BundleContext bc) throws Exception {
        Filter caFilter = getNonProxyFilter(bc, ConfigurationAdmin.class);
        configAdminTracker = new ServiceTracker<ConfigurationAdmin, ConfigurationAdmin>(bc, caFilter, null);
        configAdminTracker.open();

        Filter pmFilter = getNonProxyFilter(bc, ProxyManager.class);
        proxyManagerTracker = new ServiceTracker<ProxyManager, ProxyManager>(bc, pmFilter, null);
        proxyManagerTracker.open();
    }

    private Filter getNonProxyFilter(BundleContext bc, Class<?> clazz) throws InvalidSyntaxException {
        Filter caFilter = bc.createFilter(
                "(&(" + Constants.OBJECTCLASS + "=" + clazz.getName() +
                ")(!(" + PROXY_MARKER_KEY + "=*)))");
        return caFilter;
    }

    void close() {
        proxyManagerTracker.close();
        configAdminTracker.close();
    }

    boolean isProxy(ServiceReference<?> sr) {
        return sr.getProperty(PROXY_MARKER_KEY) != null;
    }

    void proxy(ServiceReference<?> originalRef) throws Exception {
        if (proxyMap.containsKey(originalRef)) {
            return;
        }
        if (isProxy(originalRef)) {
            return;
        }
        System.out.println("*** About to Proxy: " + originalRef);

        // make sure it's on the map before the proxy is registered, as that can trigger
        // another call into this method, and we need to make sure that it doesn't proxy
        // the service again.
        ServiceRegistrationHolder registrationHolder = new ServiceRegistrationHolder();
        proxyMap.put(originalRef, registrationHolder);

        ProxyManager pm = proxyManagerTracker.getService();
        if (pm == null) {
            throw new IllegalStateException("Proxy Manager is not found");
            // TODO queue them up and wait...
        }

        Object svc = originalRef.getBundle().getBundleContext().getService(originalRef);
        Set<Class<?>> allClasses = new HashSet<Class<?>>();
        allClasses.addAll(Arrays.asList(svc.getClass().getInterfaces()));
        allClasses.addAll(Arrays.asList(svc.getClass().getClasses()));
        allClasses.addAll(Arrays.asList(svc.getClass().getDeclaredClasses())); // TODO what is this for?
        allClasses.add(svc.getClass()); // TODO is this needed?

        for (Iterator<Class<?>> i = allClasses.iterator(); i.hasNext(); ) {
            Class<?> cls = i.next();
            int modifiers = cls.getModifiers();
            if ((modifiers & (Modifier.FINAL | Modifier.PRIVATE)) > 0) {
                // Do not attempt to proxy private or final classes
                i.remove();
            }
        }

        InvocationListener il = new ProxyInvocationListener(svc);
        Object proxyService = pm.createInterceptingProxy(originalRef.getBundle(), allClasses, svc, il);
        ServiceRegistration<?> proxyReg = originalRef.getBundle().getBundleContext().registerService(
                (String[]) originalRef.getProperty(Constants.OBJECTCLASS),
                proxyService, proxyProperties(originalRef));

        // put the actual service registration in the holder
        registrationHolder.registration = proxyReg;

        // TODO register listener that unregisters the proxy once the original service is gone.
    }

    private Dictionary<String, Object> proxyProperties(ServiceReference<?> sr) throws Exception {
        Dictionary<String, Object> p = new Hashtable<String, Object>();

        for (String key : sr.getPropertyKeys()) {
            p.put(key, sr.getProperty(key));
        }
        p.put(PROXY_MARKER_KEY, "proxy");
        return p;
    }

    private static class ServiceRegistrationHolder {
        ServiceRegistration<?> registration;
    }

    private static class ProxyInvocationListener implements InvocationListener {
        private final Object original;

        public ProxyInvocationListener(Object svc) {
            original = svc;
        }

        @Override
        public Object preInvoke(Object proxy, Method m, Object[] args) throws Throwable {
            System.out.println("*** invoking: " + m + "-" + Arrays.toString(args));
            // Cannot use the proxy object, because that causes trouble in case reflection is used to invoke this method...
            if (new Integer(42).equals(args[0])) {
                throw new SecurityException("Gotcha!");
            }
            return null; // return m.invoke(original, args);
        }

        @Override
        public void postInvokeExceptionalReturn(Object token, Object proxy, Method m, Throwable exception) throws Throwable {
            System.out.println("*** done invoking: " + m + "- exception: " + exception);
        }

        @Override
        public void postInvoke(Object token, Object proxy, Method m, Object returnValue) throws Throwable {
            System.out.println("*** done invoking: " + m + "- rc: " + returnValue);
        }
    }
}
