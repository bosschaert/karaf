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
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Dictionary;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.security.auth.Subject;

import org.apache.aries.proxy.InvocationListener;
import org.apache.aries.proxy.ProxyManager;
import org.apache.karaf.jaas.boot.principal.RolePrincipal;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.Filter;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;
import org.osgi.util.tracker.ServiceTracker;

public class GuardProxyCatalog {
    private static final String PROXY_MARKER_KEY = "." + GuardProxyCatalog.class.getName();

    private final ServiceTracker<ConfigurationAdmin, ConfigurationAdmin> configAdminTracker;
    private final ServiceTracker<ProxyManager, ProxyManager> proxyManagerTracker;
    private final ConcurrentMap<ProxyMapKey, ServiceRegistrationHolder> proxyMap =
            new ConcurrentHashMap<ProxyMapKey, ServiceRegistrationHolder>();


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

        // Remove all proxy registrations
        for (ServiceRegistrationHolder srh : proxyMap.values()) {
            srh.registration.unregister();
        }
    }

    boolean isProxy(ServiceReference<?> sr) {
        return sr.getProperty(PROXY_MARKER_KEY) != null;
    }

    boolean isProxyFor(ServiceReference<?> sr, BundleContext clientBC) {
        return new Long(clientBC.getBundle().getBundleId()).equals(sr.getProperty(PROXY_MARKER_KEY));
    }

    void proxyIfNotAlreadyProxied(ServiceReference<?> originalRef, BundleContext clientBC) throws Exception {
        if (isProxy(originalRef)) {
            // It's already a proxy, don't re-proxy
            return;
        }

        // make sure it's on the map before the proxy is registered, as that can trigger
        // another call into this method, and we need to make sure that it doesn't proxy
        // the service again.
        ProxyMapKey key = new ProxyMapKey(originalRef, clientBC);
        ServiceRegistrationHolder registrationHolder = new ServiceRegistrationHolder();
        ServiceRegistrationHolder previousHolder = proxyMap.putIfAbsent(key, registrationHolder);
        if (previousHolder != null) {
            // There is already a proxy for this service for this client bundle.
            return;
        }

        System.out.println("*** About to Proxy: " + originalRef + " for " + clientBC.getBundle().getSymbolicName());

        ProxyManager pm = proxyManagerTracker.getService();
        if (pm == null) {
            throw new IllegalStateException("Proxy Manager is not found");
            // TODO queue them up and wait...
        }

        Object svc = clientBC.getService(originalRef);
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

        String[] objectClassProp = (String[]) originalRef.getProperty(Constants.OBJECTCLASS);
        InvocationListener il = new ProxyInvocationListener(configAdminTracker, objectClassProp);
        Object proxyService = pm.createInterceptingProxy(originalRef.getBundle(), allClasses, svc, il);
        ServiceRegistration<?> proxyReg = originalRef.getBundle().getBundleContext().registerService(
                objectClassProp, proxyService, proxyProperties(originalRef, clientBC));

        // put the actual service registration in the holder
        registrationHolder.registration = proxyReg;

        // TODO register listener that unregisters the proxy once the original service is gone.
    }

    private Dictionary<String, Object> proxyProperties(ServiceReference<?> sr, BundleContext clientBC) throws Exception {
        Dictionary<String, Object> p = new Hashtable<String, Object>();

        for (String key : sr.getPropertyKeys()) {
            p.put(key, sr.getProperty(key));
        }
        p.put(PROXY_MARKER_KEY, new Long(clientBC.getBundle().getBundleId()));
        return p;
    }

    private static class ServiceRegistrationHolder {
        ServiceRegistration<?> registration;
    }

    /**
     * Key for the proxy map. Note that each service client bundle gets its own proxy as service factories
     * can cause each client to get a separate service instance.
     */
    private static class ProxyMapKey {
        private final ServiceReference<?> serviceReference;
        private final long clientBundleID;

        ProxyMapKey(ServiceReference<?> sr, BundleContext clientBC) {
            serviceReference = sr;
            clientBundleID = clientBC.getBundle().getBundleId();
        }

        @Override
        public int hashCode() {
            int result = 1;
            result = 31 * result + (int) (clientBundleID ^ (clientBundleID >>> 32));
            result = 31 * result + ((serviceReference == null) ? 0 : serviceReference.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            ProxyMapKey other = (ProxyMapKey) obj;
            if (clientBundleID != other.clientBundleID)
                return false;
            if (serviceReference == null) {
                if (other.serviceReference != null)
                    return false;
            } else if (!serviceReference.equals(other.serviceReference))
                return false;
            return true;
        }
    }

    private static class ProxyInvocationListener implements InvocationListener {
        private final String[] objectClasses;
        private final ServiceTracker<ConfigurationAdmin, ConfigurationAdmin> caTracker;

        public ProxyInvocationListener(ServiceTracker<ConfigurationAdmin, ConfigurationAdmin> caTracker, String[] objectClassProp) {
            this.caTracker = caTracker;
            this.objectClasses = objectClassProp;
        }

        @Override
        public Object preInvoke(Object proxy, Method m, Object[] args) throws Throwable {
            ConfigurationAdmin ca = caTracker.getService();
            if (ca == null) {
                return null;
            }

            Class<?> cls = m.getDeclaringClass();

            // TODO optimize!! This can be expensive!
            Configuration[] configs = ca.listConfigurations("(" + Constants.SERVICE_PID + "=service.acl." + cls.getName() + ")");
            if (configs == null || configs.length == 0) {
                return null;
            }

            // We should be getting one matching object
            Configuration config = configs[0];
            Object roleStr = config.getProperties().get(m.getName());
            if (!(roleStr instanceof String)) {
                return null;
            }

            for (String role : parseRoles((String) roleStr)) {
                if (currentUserHasRole(role)) {
                    return null;
                }
            }

            // The current user does not have the required roles to invoke the service.
            throw new SecurityException("Insufficient credentials for service invocation.");


            /*
            for (String cls : objectClasses) {
                // TODO optimize!! This can be expensive!

                Configuration[] configs = ca.listConfigurations("(" + Constants.SERVICE_PID + "=" + cls + ")");
                if (configs == null)
                    return;


            }
            */

            /*
            System.out.println("*** invoking: " + m + "-" + Arrays.toString(args));
            // Cannot use the proxy object, because that causes trouble in case reflection is used to invoke this method...
            if (new Integer(42).equals(args[0])) {
                throw new SecurityException("Gotcha!");
            }
            return null; // return m.invoke(original, args);
            */
        }


        @Override
        public void postInvokeExceptionalReturn(Object token, Object proxy, Method m, Throwable exception) throws Throwable {
        }

        @Override
        public void postInvoke(Object token, Object proxy, Method m, Object returnValue) throws Throwable {
        }
    }

    static boolean currentUserHasRole(String reqRole) {
        String clazz;
        String role;
        int idx = reqRole.indexOf(':');
        if (idx > 0) {
            clazz = reqRole.substring(0, idx);
            role = reqRole.substring(idx + 1);
        } else {
            clazz = RolePrincipal.class.getName();
            role = reqRole;
        }

        AccessControlContext acc = AccessController.getContext();
        if (acc == null) {
            return false;
        }
        Subject subject = Subject.getSubject(acc);

        if (subject == null) {
            return false;
        }

        for (Principal p : subject.getPrincipals()) {
            if (clazz.equals(p.getClass().getName()) && role.equals(p.getName())) {
                return true;
            }
        }
        return false;
    }

    static List<String> parseRoles(String roleStr) {
        int hashIdx = roleStr.indexOf('#');
        if (hashIdx >= 0) {
            // You can put a comment at the end
            roleStr = roleStr.substring(0, hashIdx);
        }

        List<String> roles = new ArrayList<String>();
        for (String role : roleStr.split("[,]")) {
            String trimmed = role.trim();
            if (trimmed.length() > 0)
                roles.add(trimmed);
        }
        return roles;
    }
}
