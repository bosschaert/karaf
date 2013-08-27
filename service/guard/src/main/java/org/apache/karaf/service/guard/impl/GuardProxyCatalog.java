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
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.regex.Pattern;

import javax.security.auth.Subject;

import org.apache.aries.proxy.InvocationListener;
import org.apache.aries.proxy.ProxyManager;
import org.apache.karaf.jaas.boot.principal.RolePrincipal;
import org.apache.karaf.service.guard.tools.ACLConfigurationParser;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.Filter;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;
import org.osgi.util.tracker.ServiceTracker;
import org.osgi.util.tracker.ServiceTrackerCustomizer;

public class GuardProxyCatalog {
    public static final String KARAF_SECURED_SERVICES_SYSPROP = "karaf.secured.services";
    public static final String SERVICE_GUARD_ROLES_PROPERTY = "org.apache.karaf.service.guard.roles";

    static final String PROXY_MARKER_KEY = "." + GuardProxyCatalog.class.getName();

    private static final Pattern JAVA_CLASS_NAME_PART_PATTERN = Pattern.compile("[a-zA-Z_$][a-zA-Z0-9_$]*");

    private final BundleContext bundleContext;
    final ServiceTracker<ConfigurationAdmin, ConfigurationAdmin> configAdminTracker;
    final ServiceTracker<ProxyManager, ProxyManager> proxyManagerTracker;
    final ConcurrentMap<ProxyMapKey, ServiceRegistrationHolder> proxyMap =
            new ConcurrentHashMap<ProxyMapKey, ServiceRegistrationHolder>();
    final BlockingQueue<CreateProxyRunnable> createProxyQueue = new LinkedBlockingQueue<CreateProxyRunnable>();
    volatile boolean runProxyCreator = true;

    GuardProxyCatalog(BundleContext bc) throws Exception {
        bundleContext = bc;

        Filter caFilter = getNonProxyFilter(bc, ConfigurationAdmin.class);
        configAdminTracker = new ServiceTracker<ConfigurationAdmin, ConfigurationAdmin>(bc, caFilter, null);
        configAdminTracker.open();

        Filter pmFilter = getNonProxyFilter(bc, ProxyManager.class);
        proxyManagerTracker = new ServiceTracker<ProxyManager, ProxyManager>(bc, pmFilter, new ServiceProxyCreatorCustomizer());
        proxyManagerTracker.open();
    }

    static Filter getNonProxyFilter(BundleContext bc, Class<?> clazz) throws InvalidSyntaxException {
        Filter caFilter = bc.createFilter(
                "(&(" + Constants.OBJECTCLASS + "=" + clazz.getName() +
                ")(!(" + PROXY_MARKER_KEY + "=*)))");
        return caFilter;
    }

    void close() {
        runProxyCreator = false;
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

    void proxyIfNotAlreadyProxied(final ServiceReference<?> originalRef, final BundleContext clientBC) throws Exception {
        if (isProxy(originalRef)) {
            // It's already a proxy, don't re-proxy
            return;
        }

        // make sure it's on the map before the proxy is registered, as that can trigger
        // another call into this method, and we need to make sure that it doesn't proxy
        // the service again.
        ProxyMapKey key = new ProxyMapKey(originalRef, clientBC);
        final ServiceRegistrationHolder registrationHolder = new ServiceRegistrationHolder();
        ServiceRegistrationHolder previousHolder = proxyMap.putIfAbsent(key, registrationHolder);
        if (previousHolder != null) {
            // There is already a proxy for this service for this client bundle.
            return;
        }

        // Instead of immediately creating the proxy, we add the code that creates the proxy to the proxyQueue.
        // This has 2 advantages:
        //  1. creating a proxy, can be processor intensive which benefits from asynchronous execution
        //  2. it also means that we can better react to the fact that the ProxyManager service might arrive
        //     later. As soon as the Proxy Manager is available, the queue is emptied and the proxies created.
        CreateProxyRunnable cpr = new CreateProxyRunnable() {
            @Override
            public void run(ProxyManager pm) throws Exception {
                List<String> objectClassProperty =
                        new ArrayList<String>(Arrays.asList((String[]) originalRef.getProperty(Constants.OBJECTCLASS)));
                Object svc = clientBC.getService(originalRef);
                Set<Class<?>> allClasses = new HashSet<Class<?>>();
                for (Iterator<String> i = objectClassProperty.iterator(); i.hasNext(); ) {
                    String cls = i.next();
                    try {
                        allClasses.add(clientBC.getBundle().loadClass(cls));
                    } catch (Exception e) {
                        // The client has no visibility of the class, so it's no use for it...
                        i.remove();
                    }
                }

                Class<?> curClass = svc.getClass();
                while (curClass != null) {
                    allClasses.addAll(Arrays.asList(curClass.getInterfaces()));
                    curClass = curClass.getSuperclass(); // Collect interfaces implemented by super types too
                }

                allClasses.add(svc.getClass());

                nextClass:
                for (Iterator<Class<?>> i = allClasses.iterator(); i.hasNext(); ) {
                    Class<?> cls = i.next();
                    if (((cls.getModifiers() & (Modifier.FINAL | Modifier.PRIVATE)) > 0) ||
                        cls.isAnonymousClass()  || cls.isLocalClass()) {
                        // Do not attempt to proxy private, final or anonymous classes
                        i.remove();
                        objectClassProperty.remove(cls.getName());
                    } else {
                        for (Method m : cls.getDeclaredMethods()) {
                            if ((m.getModifiers() & (Modifier.FINAL | Modifier.PRIVATE)) > 0) {
                                // Do not attempt to proxy classes that contain final or private methods
                                i.remove();
                                objectClassProperty.remove(cls.getName());
                                continue nextClass;
                            }
                        }
                    }
                }

                if (objectClassProperty.isEmpty()) {
                    // If there are no object classes left that the client can see, it must be one of those services
                    // that is found using other properties. In this case, register it under the Object.class.
                    objectClassProperty.add(Object.class.getName());
                }

                InvocationListener il = new ProxyInvocationListener(originalRef);
                Object proxyService = pm.createInterceptingProxy(originalRef.getBundle(), allClasses, svc, il);
                ServiceRegistration<?> proxyReg = originalRef.getBundle().getBundleContext().registerService(
                        objectClassProperty.toArray(new String [] {}), proxyService, proxyProperties(originalRef, clientBC));

                // put the actual service registration in the holder
                registrationHolder.registration = proxyReg;

                // TODO register listener that unregisters the proxy once the original service is gone.
            }
        };
        createProxyQueue.put(cpr);
    }

    private Dictionary<String, Object> proxyProperties(ServiceReference<?> sr, BundleContext clientBC) throws Exception {
        Dictionary<String, Object> p = copyProperties(sr);
        p.put(PROXY_MARKER_KEY, new Long(clientBC.getBundle().getBundleId()));
        List<String> roles = getServiceInvocationRoles(sr);
        if (roles != null) {
            p.put(SERVICE_GUARD_ROLES_PROPERTY, roles);
        }
        return p;
    }

    private Dictionary<String, Object> copyProperties(ServiceReference<?> sr) {
        Dictionary<String, Object> p = new Hashtable<String, Object>();

        for (String key : sr.getPropertyKeys()) {
            p.put(key, sr.getProperty(key));
        }
        return p;
    }

    // Returns what roles can possibly ever invoke this service. Note that not every invocation may be successful
    // as there can be different roles for different methos and also roles based on arguments passed in.
    private List<String> getServiceInvocationRoles(ServiceReference<?> serviceReference) throws Exception {
        // TODO very similar to what happens in the ProxyInvocationListener
        ConfigurationAdmin ca = configAdminTracker.getService();
        if (ca == null) {
            return null;
        }

        // TODO optimize!! This can be expensive!
        Configuration[] configs = ca.listConfigurations("(service.guard=*)");
        if (configs == null || configs.length == 0) {
            return null;
        }

        List<String> allRoles = new ArrayList<String>();
        for (Configuration config : configs) {
            Object guardFilter = config.getProperties().get("service.guard");
            if (guardFilter instanceof String) {
                Filter filter = bundleContext.createFilter((String) guardFilter);
                if (filter.match(serviceReference)) {
                    for (Enumeration<String> e = config.getProperties().keys(); e.hasMoreElements(); ) {
                        String key = e.nextElement();
                        String bareKey = key;
                        int idx = bareKey.indexOf('(');
                        if (idx >= 0) {
                            bareKey = bareKey.substring(0, idx);
                        }
                        int idx2 = bareKey.indexOf('*');
                        if (idx2 >= 0) {
                            bareKey = bareKey.substring(0, idx2);
                        }
                        if (!isValidMethodName(bareKey)) {
                            continue;
                        }
                        Object value = config.getProperties().get(key);
                        if (value instanceof String) {
                            allRoles.addAll(ACLConfigurationParser.parseRoles((String) value));
                        }
                    }
                }
            }
        }
        return allRoles;
    }

    private boolean isValidMethodName(String name) {
        return JAVA_CLASS_NAME_PART_PATTERN.matcher(name).matches();
    }

    static class ServiceRegistrationHolder {
        volatile ServiceRegistration<?> registration;
    }

    /**
     * Key for the proxy map. Note that each service client bundle gets its own proxy as service factories
     * can cause each client to get a separate service instance.
     */
    static class ProxyMapKey {
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

    private class ProxyInvocationListener implements InvocationListener {
        private final ServiceReference<?> serviceReference;

        public ProxyInvocationListener(ServiceReference<?> sr) {
            this.serviceReference = sr;
        }

        @Override
        public Object preInvoke(Object proxy, Method m, Object[] args) throws Throwable {
            ConfigurationAdmin ca = configAdminTracker.getService();
            if (ca == null) {
                return null;
            }

            // TODO optimize!! This can be expensive!
            Configuration[] configs = ca.listConfigurations("(service.guard=*)");
            if (configs == null || configs.length == 0) {
                return null;
            }

            // The service properties against which is matched only contain the object class of the current
            // method, otherwise there can be contamination across ACLs
            Dictionary<String, Object> serviceProps = copyProperties(serviceReference);
            serviceProps.put(Constants.OBJECTCLASS, new String [] {m.getDeclaringClass().getName()});

            String[] sig = new String[m.getParameterTypes().length];
            for (int i = 0; i < m.getParameterTypes().length; i++) {
                sig[i] = m.getParameterTypes()[i].getName();
            }

            for (Configuration config : configs) {
                Object guardFilter = config.getProperties().get("service.guard");
                if (guardFilter instanceof String) {
                    Filter filter = bundleContext.createFilter((String) guardFilter);
                    if (filter.match(serviceProps)) {
                        List<String> roles = ACLConfigurationParser.
                                getRolesForInvocation(m.getName(), args, sig, config.getProperties());
                        if (roles != null) {
                            for (String role : roles) {
                                if (currentUserHasRole(role)) {
                                    return null;
                                }
                            }
                            // The current user does not have the required roles to invoke the service.
                            throw new SecurityException("Insufficient credentials.");
                        }
                    }
                }
            }

            return null;
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

    class ServiceProxyCreatorCustomizer implements ServiceTrackerCustomizer<ProxyManager, ProxyManager> {
        @Override
        public ProxyManager addingService(ServiceReference<ProxyManager> reference) {
            runProxyCreator = true;
            final ProxyManager svc = bundleContext.getService(reference);
            if (svc != null) {
                newProxyProducingThread(svc);
            }
            return svc;
        }

        private void newProxyProducingThread(final ProxyManager proxyManager) {
            Thread t = new Thread(new Runnable() {
                @Override
                public void run() {
                    while (runProxyCreator) {
                        try {
                            CreateProxyRunnable proxyCreator = createProxyQueue.take();
                            proxyCreator.run(proxyManager);
                        } catch (Exception e) {
                            // TODO Log
                            e.printStackTrace();
                        }
                    }
                }
            });
            t.setName("Secure OSGi Service Proxy Creator");
            t.setDaemon(true);
            t.start();
        }

        @Override
        public void modifiedService(ServiceReference<ProxyManager> reference, ProxyManager service) {
            // no need to react
        }

        @Override
        public void removedService(ServiceReference<ProxyManager> reference, ProxyManager service) {
            runProxyCreator = false; // Will end the proxy creation thread
        }
    }

    interface CreateProxyRunnable {
        void run(ProxyManager pm) throws Exception;
    }
}
