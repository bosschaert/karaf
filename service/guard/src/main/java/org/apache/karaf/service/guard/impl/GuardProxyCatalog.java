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

import java.io.IOException;
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
import java.util.Map;
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
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.BundleEvent;
import org.osgi.framework.BundleListener;
import org.osgi.framework.Constants;
import org.osgi.framework.Filter;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceEvent;
import org.osgi.framework.ServiceListener;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;
import org.osgi.util.tracker.ServiceTracker;
import org.osgi.util.tracker.ServiceTrackerCustomizer;

public class GuardProxyCatalog implements ServiceListener, BundleListener {
    public static final String KARAF_SECURED_SERVICES_SYSPROP = "karaf.secured.services";
    public static final String SERVICE_GUARD_ROLES_PROPERTY = "org.apache.karaf.service.guard.roles";

    static final String PROXY_CREATOR_THREAD_NAME = "Secure OSGi Service Proxy Creator";
    static final String PROXY_FOR_BUNDLE_KEY = "." + GuardProxyCatalog.class.getName() + ".org-bundle";
    static final String PROXY_FOR_SERVICE_KEY = "." + GuardProxyCatalog.class.getName() + ".org-service";

    private static final Pattern JAVA_CLASS_NAME_PART_PATTERN = Pattern.compile("[a-zA-Z_$][a-zA-Z0-9_$]*");

    private final BundleContext bundleContext;
    final ServiceTracker<ConfigurationAdmin, ConfigurationAdmin> configAdminTracker;
    final ServiceTracker<ProxyManager, ProxyManager> proxyManagerTracker;
    final ConcurrentMap<ProxyMapKey, ServiceRegistrationHolder> proxyMap =
            new ConcurrentHashMap<ProxyMapKey, ServiceRegistrationHolder>();
    final BlockingQueue<CreateProxyRunnable> createProxyQueue = new LinkedBlockingQueue<CreateProxyRunnable>();

    // These two variables control the proxy creator thread, which is started as soon as a ProxyManager Service
    // becomes available.
    volatile boolean runProxyCreator = true;
    volatile Thread proxyCreatorThread = null;

    GuardProxyCatalog(BundleContext bc) throws Exception {
        bundleContext = bc;

        // The service listener is used to update/unregister proxies if the backing service changes/goes away
        bc.addServiceListener(this);
        // The bundle listener is used to unregister proxies for client that go away
        bc.addBundleListener(this);

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
                ")(!(" + PROXY_FOR_BUNDLE_KEY + "=*)))");
        return caFilter;
    }

    void close() {
        stopProxyCreator();
        proxyManagerTracker.close();
        configAdminTracker.close();

        bundleContext.removeBundleListener(this);
        bundleContext.removeServiceListener(this);

        // Remove all proxy registrations
        for (Iterator<Map.Entry<ProxyMapKey, ServiceRegistrationHolder>> i = proxyMap.entrySet().iterator(); i.hasNext(); ) {
            unregisterProxy(i.next());
        }
    }

    @Override
    public void serviceChanged(ServiceEvent event) {
        // This method is to ensure that proxied services follow the original service. I.e. if the original service
        // goes away the proxies should go away too. If the original service is modified, the proxies should be
        // modified accordingly

        ServiceReference<?> sr = event.getServiceReference();
        if (event.getType() == ServiceEvent.REGISTERED) {
            // Nothing to do for new services
            return;
        }

        if (isProxy(sr)) {
            // Ignore proxies, we only react to real service changes
            return;
        }

        if (event.getType() == ServiceEvent.UNREGISTERING) {
            handleOriginalServiceUnregistering((Long) sr.getProperty(Constants.SERVICE_ID));
        }

        if ((event.getType() & (ServiceEvent.MODIFIED | ServiceEvent.MODIFIED_ENDMATCH)) > 0) {
            handleOriginalServiceModifed(sr);
        }
    }

    private void handleOriginalServiceUnregistering(long orgServiceID) {
        for (Iterator<CreateProxyRunnable> i = createProxyQueue.iterator(); i.hasNext(); ) {
            CreateProxyRunnable cpr = i.next();
            if (cpr.getOriginalServiceID() == orgServiceID) {
                i.remove();
            }
        }

        for (Iterator<Map.Entry<ProxyMapKey, ServiceRegistrationHolder>> i = proxyMap.entrySet().iterator(); i.hasNext(); ) {
            Map.Entry<ProxyMapKey, ServiceRegistrationHolder> entry = i.next();
            if (entry.getKey().serviceReference.getProperty(Constants.SERVICE_ID).equals(orgServiceID)) {
                i.remove();
                unregisterProxy(entry);
            }
        }
    }

    private void handleOriginalServiceModifed(ServiceReference<?> orgServiceRef) {
        // We don't need to do anything for services that are queued up to be proxied, as the
        // properties are only taken at the point of proxyfication...

        for (Iterator<Map.Entry<ProxyMapKey, ServiceRegistrationHolder>> i = proxyMap.entrySet().iterator(); i.hasNext(); ) {
            Map.Entry<ProxyMapKey, ServiceRegistrationHolder> entry = i.next();
            if (entry.getKey().serviceReference.equals(orgServiceRef)) {
                ServiceRegistration<?> reg = entry.getValue().registration;
                if (reg != null) {
                    // Preserve the roles as they are expensive to compute
                    Object roles = reg.getReference().getProperty(SERVICE_GUARD_ROLES_PROPERTY);
                    Dictionary<String, Object> newProxyProps = proxyProperties(
                            orgServiceRef, entry.getKey().clientBundleContext.getBundle().getBundleId(),
                            (Long) orgServiceRef.getProperty(Constants.SERVICE_ID));
                    newProxyProps.put(SERVICE_GUARD_ROLES_PROPERTY, roles);
                    reg.setProperties(newProxyProps);
                }
            }
        }
    }

    @Override
    public void bundleChanged(BundleEvent event) {
        if (event.getType() != BundleEvent.STOPPING) {
            return;
        }

        Bundle stoppingBundle = event.getBundle();
        long stoppingBundleID = stoppingBundle.getBundleId();
        BundleContext stoppingBC = stoppingBundle.getBundleContext();
        if (stoppingBC.equals(bundleContext) || stoppingBundleID == 0) {
            // Don't react to this bundle stopping or the system bundle
            return;
        }

        for (Iterator<CreateProxyRunnable> i = createProxyQueue.iterator(); i.hasNext(); ) {
            CreateProxyRunnable cpr = i.next();
            if (stoppingBC.equals(cpr.getClientBundleContext())) {
                i.remove();
            }
        }

        for (Iterator<Map.Entry<ProxyMapKey, ServiceRegistrationHolder>> i = proxyMap.entrySet().iterator(); i.hasNext(); ) {
            Map.Entry<ProxyMapKey, ServiceRegistrationHolder> entry = i.next();
            if (stoppingBC.equals(entry.getKey().clientBundleContext)) {
                i.remove();
                unregisterProxy(entry);
            }
        }
    }

    boolean isProxy(ServiceReference<?> sr) {
        return sr.getProperty(PROXY_FOR_BUNDLE_KEY) != null;
    }

    boolean isProxyFor(ServiceReference<?> sr, BundleContext clientBC) {
        return new Long(clientBC.getBundle().getBundleId()).equals(sr.getProperty(PROXY_FOR_BUNDLE_KEY));
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

        final long orgServiceID = (Long) originalRef.getProperty(Constants.SERVICE_ID);

        // Instead of immediately creating the proxy, we add the code that creates the proxy to the proxyQueue.
        // This has 2 advantages:
        //  1. creating a proxy, can be processor intensive which benefits from asynchronous execution
        //  2. it also means that we can better react to the fact that the ProxyManager service might arrive
        //     later. As soon as the Proxy Manager is available, the queue is emptied and the proxies created.
        CreateProxyRunnable cpr = new CreateProxyRunnable() {
            @Override
            public BundleContext getClientBundleContext() {
                return clientBC;
            }

            @Override
            public long getOriginalServiceID() {
                return orgServiceID;
            }

            @Override
            public void run(ProxyManager pm) throws Exception {
                List<String> objectClassProperty =
                        new ArrayList<String>(Arrays.asList((String[]) originalRef.getProperty(Constants.OBJECTCLASS)));

                // This needs to be done on the Client BundleContext since the bundle might be backed by a Service Factory
                // in which case it needs to be given a chance to produce the right service for this client.
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
                        objectClassProperty.toArray(new String [] {}), proxyService, proxyPropertiesRoles());

                // put the actual service registration in the holder
                registrationHolder.registration = proxyReg;
            }

            private Dictionary<String, Object> proxyPropertiesRoles() throws Exception {
                Dictionary<String, Object> p = proxyProperties(originalRef, clientBC.getBundle().getBundleId(), orgServiceID);

                List<String> roles = getServiceInvocationRoles(originalRef);
                p.put(SERVICE_GUARD_ROLES_PROPERTY, roles);
                return p;
            }
        };
        createProxyQueue.put(cpr);
    }

    private static void unregisterProxy(Map.Entry<ProxyMapKey, ServiceRegistrationHolder> entry) {
        ProxyMapKey pmk = entry.getKey();

        // The following line is needed because we call clientBC.getService() when the proxy is created
        pmk.clientBundleContext.ungetService(pmk.serviceReference);

        ServiceRegistration<?> reg = entry.getValue().registration;
        if (reg != null) {
            reg.unregister();
        }
    }

    private static Dictionary<String, Object> proxyProperties(ServiceReference<?> sr, Long clientBundleID, Long orgServiceID) {
        Dictionary<String, Object> p = copyProperties(sr);
        p.put(PROXY_FOR_BUNDLE_KEY, clientBundleID);
        p.put(PROXY_FOR_SERVICE_KEY, orgServiceID);
        return p;
    }

    private static Dictionary<String, Object> copyProperties(ServiceReference<?> sr) {
        Dictionary<String, Object> p = new Hashtable<String, Object>();

        for (String key : sr.getPropertyKeys()) {
            p.put(key, sr.getProperty(key));
        }
        return p;
    }

    // Returns what roles can possibly ever invoke this service. Note that not every invocation may be successful
    // as there can be different roles for different methos and also roles based on arguments passed in.
    private List<String> getServiceInvocationRoles(ServiceReference<?> serviceReference) throws Exception {
        List<String> allRoles = new ArrayList<String>();

        // This can probably be optimized. Maybe we can cache the config object relevant instead of
        // walking through all of the ones that have 'service.guard'.
        for (Configuration config : getServiceGuardConfigs()) {
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

    // Ensures that it never returns null
    private Configuration[] getServiceGuardConfigs() throws IOException, InvalidSyntaxException {
        ConfigurationAdmin ca = configAdminTracker.getService();
        if (ca == null) {
            return new Configuration [] {};
        }

        Configuration[] configs = ca.listConfigurations("(service.guard=*)");
        if (configs == null) {
            return new Configuration [] {};
        }
        return configs;
    }

    private boolean isValidMethodName(String name) {
        return JAVA_CLASS_NAME_PART_PATTERN.matcher(name).matches();
    }

    void stopProxyCreator() {
        runProxyCreator = false; // Will end the proxy creation thread
        if (proxyCreatorThread != null) {
            proxyCreatorThread.interrupt();
        }
    }

    static class ServiceRegistrationHolder {
        volatile ServiceRegistration<?> registration;
    }

    /**
     * Key for the proxy map. Note that each service client bundle gets its own proxy as service factories
     * can cause each client to get a separate service instance.
     */
    static class ProxyMapKey {
        final ServiceReference<?> serviceReference;
        final BundleContext clientBundleContext;

        ProxyMapKey(ServiceReference<?> sr, BundleContext clientBC) {
            serviceReference = sr;
            clientBundleContext = clientBC;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((clientBundleContext == null) ? 0 : clientBundleContext.hashCode());
            result = prime * result + ((serviceReference == null) ? 0 : serviceReference.hashCode());
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
            if (clientBundleContext == null) {
                if (other.clientBundleContext != null)
                    return false;
            } else if (!clientBundleContext.equals(other.clientBundleContext))
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
            Configuration[] configs = getServiceGuardConfigs();
            if (configs.length == 0) {
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

            // This can probably be optimized. Maybe we can cache the config object relevant instead of
            // walking through all of the ones that have 'service.guard'.
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
            if (proxyCreatorThread == null && svc != null) {
                proxyCreatorThread = newProxyProducingThread(svc);
            }
            return svc;
        }

        private Thread newProxyProducingThread(final ProxyManager proxyManager) {
            Thread t = new Thread(new Runnable() {
                @Override
                public void run() {
                    while (runProxyCreator) {
                        try {
                            CreateProxyRunnable proxyCreator = createProxyQueue.take();
                            proxyCreator.run(proxyManager);
                        } catch (InterruptedException ie) {
                            // part of normal behaviour
                        } catch (Exception e) {
                            // TODO Log
                            e.printStackTrace();
                        }
                    }
                    // finished running
                    proxyCreatorThread = null;
                }
            });
            t.setName(PROXY_CREATOR_THREAD_NAME);
            t.setDaemon(true);
            t.start();

            return t;
        }

        @Override
        public void modifiedService(ServiceReference<ProxyManager> reference, ProxyManager service) {
            // no need to react
        }

        @Override
        public void removedService(ServiceReference<ProxyManager> reference, ProxyManager service) {
            stopProxyCreator();
        }
    }

    interface CreateProxyRunnable {
        long getOriginalServiceID();
        BundleContext getClientBundleContext();
        void run(ProxyManager pm) throws Exception;
    }
}
