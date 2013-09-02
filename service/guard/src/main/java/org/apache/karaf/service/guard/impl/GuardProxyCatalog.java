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
import java.util.TreeMap;
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
import org.apache.karaf.service.guard.tools.ACLConfigurationParser.Specificity;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GuardProxyCatalog implements ServiceListener, BundleListener {
    public static final String KARAF_SECURED_SERVICES_SYSPROP = "karaf.secured.services";
    public static final String SERVICE_GUARD_ROLES_PROPERTY = "org.apache.karaf.service.guard.roles";

    static final String PROXY_CREATOR_THREAD_NAME = "Secure OSGi Service Proxy Creator";
    static final String PROXY_FOR_BUNDLE_KEY = "." + GuardProxyCatalog.class.getName() + ".for-bundle";
    static final Logger log = LoggerFactory.getLogger(GuardProxyCatalog.class);

    private static final Pattern JAVA_CLASS_NAME_PART_PATTERN = Pattern.compile("[a-zA-Z_$][a-zA-Z0-9_$]*");

    private final BundleContext myBundleContext;
    private final long myBundleID; // the bundlecontext isn't always available

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
        log.trace("Starting GuardProxyCatalog");
        myBundleContext = bc;
        myBundleID = bc.getBundle().getBundleId();

        // The service listener is used to update/unregister proxies if the backing service changes/goes away
        bc.addServiceListener(this);
        // The bundle listener is used to unregister proxies for client that go away
        bc.addBundleListener(this);

        Filter caFilter = getNonProxyFilter(bc, ConfigurationAdmin.class);
        log.trace("Creating Config Admin Tracker using filter {}", caFilter);
        configAdminTracker = new ServiceTracker<ConfigurationAdmin, ConfigurationAdmin>(bc, caFilter, null);
        configAdminTracker.open();

        Filter pmFilter = getNonProxyFilter(bc, ProxyManager.class);
        log.trace("Creating Proxy Manager Tracker using filter {}", pmFilter);
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
        log.trace("Stopping GuardProxyCatalog");
        stopProxyCreator();
        proxyManagerTracker.close();
        configAdminTracker.close();

        myBundleContext.removeBundleListener(this);
        myBundleContext.removeServiceListener(this);

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
            if (entry.getKey().originalServiceID == orgServiceID) {
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
            if (orgServiceRef.getProperty(Constants.SERVICE_ID).equals(entry.getKey().originalServiceID)) {
                ServiceRegistration<?> reg = entry.getValue().registration;
                if (reg != null) {
                    // Preserve the roles as they are expensive to compute
                    Object roles = reg.getReference().getProperty(SERVICE_GUARD_ROLES_PROPERTY);
                    Dictionary<String, Object> newProxyProps = proxyProperties(
                            orgServiceRef, entry.getKey().clientBundleID,
                            (Long) orgServiceRef.getProperty(Constants.SERVICE_ID));
                    newProxyProps.put(SERVICE_GUARD_ROLES_PROPERTY, roles);
                    reg.setProperties(newProxyProps);
                }
            }
        }
    }

    @Override
    public void bundleChanged(BundleEvent event) {
        if (event.getType() != BundleEvent.STOPPED) {
            return;
        }

        Bundle stoppingBundle = event.getBundle();
        long stoppingBundleID = stoppingBundle.getBundleId();
        if ((stoppingBundleID == myBundleID) || (stoppingBundleID == 0)) {
            // Don't react to this bundle stopping or the system bundle
            return;
        }

        for (Iterator<CreateProxyRunnable> i = createProxyQueue.iterator(); i.hasNext(); ) {
            CreateProxyRunnable cpr = i.next();
            if (stoppingBundleID == cpr.getClientBundleID()) {
                i.remove();
            }
        }

        for (Iterator<Map.Entry<ProxyMapKey, ServiceRegistrationHolder>> i = proxyMap.entrySet().iterator(); i.hasNext(); ) {
            Map.Entry<ProxyMapKey, ServiceRegistrationHolder> entry = i.next();
            if (stoppingBundleID == entry.getKey().clientBundleID) {
                i.remove();
                unregisterProxy(entry);
            }
        }
    }

    private String getEventType(BundleEvent event) {
        switch(event.getType()) {
        case BundleEvent.INSTALLED: return "INSTALLED";
        case BundleEvent.RESOLVED: return "RESOLVED";
        case BundleEvent.LAZY_ACTIVATION: return "LAZY_ACTIVATION";
        case BundleEvent.STARTING: return "STARTING";
        case BundleEvent.STARTED: return "STARTED";
        case BundleEvent.STOPPING: return "STOPPING";
        case BundleEvent.STOPPED: return "STOPPED";
        case BundleEvent.UPDATED: return "UPDATED";
        case BundleEvent.UNRESOLVED: return "UNRESOLVED";
        case BundleEvent.UNINSTALLED: return "UNINSTALLED";
        }
        return null;
    }

    boolean isProxy(ServiceReference<?> sr) {
        return sr.getProperty(PROXY_FOR_BUNDLE_KEY) != null;
    }

    boolean isProxyFor(ServiceReference<?> sr, BundleContext clientBC) {
        return new Long(clientBC.getBundle().getBundleId()).equals(sr.getProperty(PROXY_FOR_BUNDLE_KEY));
    }

    void proxyIfNotAlreadyProxied(final ServiceReference<?> originalRef, final BundleContext clientBC)  {
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
        final long clientBundleID = clientBC.getBundle().getBundleId();
        log.trace("Will create proxy of service {}({}) for client {}({})",
                originalRef.getProperty(Constants.OBJECTCLASS), orgServiceID,
                clientBC.getBundle().getSymbolicName(), clientBundleID);

        // Instead of immediately creating the proxy, we add the code that creates the proxy to the proxyQueue.
        // This has 2 advantages:
        //  1. creating a proxy, can be processor intensive which benefits from asynchronous execution
        //  2. it also means that we can better react to the fact that the ProxyManager service might arrive
        //     later. As soon as the Proxy Manager is available, the queue is emptied and the proxies created.
        CreateProxyRunnable cpr = new CreateProxyRunnable() {
            @Override
            public long getClientBundleID() {
                return clientBundleID;
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

                Dictionary<String, Object> actualProxyProps = copyProperties(proxyReg.getReference());
                log.info("Created proxy of service {} under {} with properties {}",
                        orgServiceID, actualProxyProps.get(Constants.OBJECTCLASS), actualProxyProps);

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

        try {
            createProxyQueue.put(cpr);
        } catch (InterruptedException e) {
            log.warn("Problem scheduling a proxy creator for service {}({})",
                    originalRef.getProperty(Constants.OBJECTCLASS), orgServiceID, e);
            e.printStackTrace();
        }
    }

    private static void unregisterProxy(Map.Entry<ProxyMapKey, ServiceRegistrationHolder> entry) {
        ServiceRegistration<?> reg = entry.getValue().registration;
        if (reg != null) {
            log.info("Unregistering proxy service of {} with properties {}",
                    reg.getReference().getProperty(Constants.OBJECTCLASS), copyProperties(reg.getReference()));
            reg.unregister();
        }
    }

    private static Dictionary<String, Object> proxyProperties(ServiceReference<?> sr, Long clientBundleID, Long orgServiceID) {
        Dictionary<String, Object> p = copyProperties(sr);
        p.put(PROXY_FOR_BUNDLE_KEY, clientBundleID);
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
                Filter filter = myBundleContext.createFilter((String) guardFilter);
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
        final long originalServiceID;
        final long clientBundleID;

        ProxyMapKey(ServiceReference<?> originalSR, BundleContext clientBC) {
            originalServiceID = (Long) originalSR.getProperty(Constants.SERVICE_ID);
            clientBundleID = clientBC.getBundle().getBundleId();
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + (int) (clientBundleID ^ (clientBundleID >>> 32));
            result = prime * result + (int) (originalServiceID ^ (originalServiceID >>> 32));
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
            if (originalServiceID != other.originalServiceID)
                return false;
            return true;
        }

        @Override
        public String toString() {
            return "ProxyMapKey [originalServiceID=" + originalServiceID + ", clientBundleID=" + clientBundleID + "]";
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

            String[] sig = new String[m.getParameterTypes().length];
            for (int i = 0; i < m.getParameterTypes().length; i++) {
                sig[i] = m.getParameterTypes()[i].getName();
            }

            // The ordering of the keys is important
            TreeMap<Specificity, List<String>> roleMappings = new TreeMap<ACLConfigurationParser.Specificity, List<String>>();

            // This can probably be optimized. Maybe we can cache the config object relevant instead of
            // walking through all of the ones that have 'service.guard'.
            for (Configuration config : configs) {
                Object guardFilter = config.getProperties().get("service.guard");
                if (guardFilter instanceof String) {
                    Filter filter = myBundleContext.createFilter((String) guardFilter);
                    if (filter.match(serviceReference)) {
                        List<String> roles = new ArrayList<String>();
                        Specificity s = ACLConfigurationParser.
                                getRolesForInvocation(m.getName(), args, sig, config.getProperties(), roles);
                        if (s != Specificity.NO_MATCH) {
                            roleMappings.put(s, roles);
                            if (s == Specificity.ARGUMENT_MATCH) {
                                // No more specific mapping can be found
                                break;
                            }
                        }
                    }
                }
            }

            if (roleMappings.size() == 0) {
                // No mappings for this method, anyone can invoke
                return null;
            }

            List<String> roles = roleMappings.values().iterator().next();
            for (String role : roles) {
                if (currentUserHasRole(role)) {
                    log.trace("Allowed user with role {} to invoke service {} method {}", role, serviceReference, m);
                    return null;
                }
            }

            // The current user does not have the required roles to invoke the service.
            log.info("Current user does not have required roles ({}) for service {} method {} and/or arguments",
                    roles, serviceReference, m);
            throw new SecurityException("Insufficient credentials.");
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
            final ProxyManager svc = myBundleContext.getService(reference);
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
                        CreateProxyRunnable proxyCreator = null;
                        try {
                            proxyCreator = createProxyQueue.take();
                        } catch (InterruptedException e1) {
                            // part of normal behaviour
                        }

                        if (proxyCreator != null) {
                            try {
                                proxyCreator.run(proxyManager);
                            } catch (Exception e) {
                                log.warn("Problem creating secured service proxy", e);
                            }
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
        long getClientBundleID();
        void run(ProxyManager pm) throws Exception;
    }
}
