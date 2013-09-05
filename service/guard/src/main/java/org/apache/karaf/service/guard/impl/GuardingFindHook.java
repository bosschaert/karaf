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

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Pattern;

import org.osgi.framework.BundleContext;
import org.osgi.framework.BundleEvent;
import org.osgi.framework.BundleListener;
import org.osgi.framework.Filter;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.hooks.service.FindHook;
import org.osgi.util.tracker.ServiceTracker;

class GuardingFindHook implements FindHook, BundleListener {
    // This regexp is used to convert filters that say something about the roles that can invoke a service
    // into a filter that doesn't have this condition. This is used to create secured/proxied versions if
    // those services arrive after the initial find operation is done.
    // The filter actually matches filters like this (and is flexible wrt spaces):
    //   (org.apache.karaf.service.guard.roles=myrole)
    // or
    //   !(org.apache.karaf.service.guard.roles=myotherrole)
    // It is then later used to turn this condition off, so that services that match the base conditions are found.
    private static final Pattern GUARD_ROLES_CONDITION =
            Pattern.compile("[!]?\\s*\\(\\s*" + GuardProxyCatalog.SERVICE_GUARD_ROLES_PROPERTY + "\\s*[=]\\s*[a-zA-Z0-9*]+\\s*\\)");

    private final BundleContext myBundleContext;
    private final GuardProxyCatalog guardProxyCatalog;
    private final Filter servicesFilter;
    final Map<String, MultiplexingServiceTracker> trackers = new HashMap<String, MultiplexingServiceTracker>();

    GuardingFindHook(BundleContext myBC, GuardProxyCatalog gpc, Filter securedServicesFilter) {
        myBundleContext = myBC;
        guardProxyCatalog = gpc;
        servicesFilter = securedServicesFilter;

        myBC.addBundleListener(this);
    }

    void close() {
        myBundleContext.removeBundleListener(this);
    }

    @Override
    public void find(BundleContext context, String name, String filter, boolean allServices,
            Collection<ServiceReference<?>> references) {
        if (servicesFilter == null) {
            return;
        }

        if (filter != null) {
//            asasasd TODO
//            this keeps recursing....
//            should only do this on a positive condition
//            or if the condition is new...
            if (filter.contains(GuardProxyCatalog.SERVICE_GUARD_ROLES_PROPERTY)) {
                // Someone is looking for a service based on roles. As the roles are added by the proxy we need
                // to start looking for services without those roles and proxy them if needed.
                addNonRoleServiceTracker(context, filter);
            }
        }

        if (myBundleContext.equals(context) || context.getBundle().getBundleId() == 0) {
            // don't hide anything from this bundle or the system bundle
            return;
        }

        for (Iterator<ServiceReference<?>> i = references.iterator(); i.hasNext(); ) {
            ServiceReference<?> sr = i.next();

            if (!servicesFilter.match(sr)) {
                continue; // TODO remove
            }

            if (guardProxyCatalog.isProxy(sr)) {
                if (!guardProxyCatalog.isProxyFor(sr, context)) {
                    i.remove();
                }
                continue;
            }

            if (!guardProxyCatalog.needsProxy(sr)) {
                continue;
            }

//            if (!guardProxyCatalog.isProxyFor(sr, context)) {
                i.remove();
                guardProxyCatalog.proxyIfNotAlreadyProxied(sr, context); // Note does most of the work async
//            }

        }
    }

    // Find was called for a service based on the roles property that is added by GuardProxyCatalog proxy mechanism
    // However, a backing/real service that matches the properties other than the roles might arrive later. We want
    // to ensure that the proxyfied service is registered when it does.
    // This method kicks off a process that adds a ServiceTracker that gets notified if such a service ever arrives.
    private void addNonRoleServiceTracker(final BundleContext context, final String filter) {
        // Replace the condition on the roles with a condition on services that don't specify the role at all
        String nonRoleFilter = GUARD_ROLES_CONDITION.matcher(filter).replaceAll("@");
        nonRoleFilter = nonRoleFilter.replaceAll("\\(\\s*[@]\\s*\\)", "@");
        nonRoleFilter = nonRoleFilter.replaceAll("[@]+", "(!(" + GuardProxyCatalog.SERVICE_GUARD_ROLES_PROPERTY + "=*))");

        // Find/create a new MST. This tracker will track the filter for a number of bundle contexts.
        boolean newTracker = false;
        MultiplexingServiceTracker mst;
        synchronized (trackers) {
            mst = trackers.get(nonRoleFilter);
            if (mst == null) {
                try {
                    mst = new MultiplexingServiceTracker(myBundleContext, context, nonRoleFilter);
                    trackers.put(nonRoleFilter, mst);
                    newTracker = true;
                } catch (InvalidSyntaxException e) {
                    GuardProxyCatalog.log.warn("Problem creating tracker for requested service without roles condition: {} ",
                            nonRoleFilter, e);
                    return;
                }
            }
        }

        if (newTracker) {
            // Important to pass true as we are tracking for other bundles.
            mst.open(true);
        } else {
            mst.addBundleContext(context);
        }
    }

    @Override
    public void bundleChanged(BundleEvent event) {
        if (event.getType() != BundleEvent.STOPPED) {
            return;
        }

        // If the bundle that is being stopped has service tracker behaviour associated, stop that behaviour
        BundleContext stoppingBC = event.getBundle().getBundleContext();
        synchronized (trackers) {
            for (Iterator<MultiplexingServiceTracker> i = trackers.values().iterator(); i.hasNext(); ) {
                MultiplexingServiceTracker mst = i.next();
                if (!mst.removeBundleContext(stoppingBC)) {
                    // No bundle contexts left in the mst, so remove from the map
                    i.remove();
                }
            }
        }
    }

    // This Service Tracker tracks services and once it finds any matches will create proxies for all clients that need it proxied.
    // It can be useful if the client looks for the roles property which is specified on the proxy but not on the original service.
    class MultiplexingServiceTracker extends ServiceTracker<Object, Object> {
        List<BundleContext> clientBCs = new CopyOnWriteArrayList<BundleContext>();

        MultiplexingServiceTracker(BundleContext context, BundleContext clientContext, String filter) throws InvalidSyntaxException {
            super(context, context.createFilter(filter), null);
            addBundleContext(clientContext);
        }

        void addBundleContext(BundleContext bc) {
            if (bc.equals(myBundleContext) || bc.getBundle().getBundleId() == 0) {
                // don't proxy anything for myself or the system bundle
                return;
            }
            clientBCs.add(bc);
        }

        boolean removeBundleContext(BundleContext bc) {
            clientBCs.remove(bc);
            if (clientBCs.isEmpty()) {
                // If nobody is interested any more, close myself
                close();
                return false;
            }
            return true;
        }

        @Override
        public Object addingService(ServiceReference<Object> reference) {
            // So there is a new service that matches the filter.
            // We now need to make sure that there is are matching proxies for it too
            // to that all the interested clients can see it...
            for (BundleContext bc : clientBCs) {
                if (servicesFilter.match(reference)) {
                    guardProxyCatalog.proxyIfNotAlreadyProxied(reference, bc);
                }
            }
            return super.addingService(reference);
        }

        // No need to listen for modifiedService/removedService as once the service is proxied, the GuardProxyCatalog tracks it
    }
}
