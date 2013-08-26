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
import org.osgi.framework.Filter;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.hooks.service.FindHook;
import org.osgi.util.tracker.ServiceTracker;

public class GuardingFindHook implements FindHook {
    private static final Pattern GUARD_ROLES_CONDITION =
            Pattern.compile("[!]?\\s*\\(\\s*" + GuardProxyCatalog.SERVICE_GUARD_ROLES_PROPERTY + "\\s*[=]\\s*[a-zA-Z0-9*]+\\s*\\)");

    private final BundleContext myBundleContext;
    private final GuardProxyCatalog guardProxyCatalog;
    final Filter servicesFilter;
    private final Map<String, MultiplexingServiceTracker> trackers = new HashMap<String, MultiplexingServiceTracker>();

    public GuardingFindHook(BundleContext myBC, GuardProxyCatalog gpc, Filter securedServicesFilter) {
        myBundleContext = myBC;
        guardProxyCatalog = gpc;
        servicesFilter = securedServicesFilter;
    }

    @Override
    public void find(BundleContext context, String name, String filter, boolean allServices,
            Collection<ServiceReference<?>> references) {

        /*
        if (filter.contains("foo")) {
            System.out.println("FINDHOOK: " + filter);
        }
        */

        if (filter.contains(GuardProxyCatalog.SERVICE_GUARD_ROLES_PROPERTY)) {
            // TODO should we only do this when nothing was returned? Probably better to do it always?
            // Someone is looking for a service based on roles, trigger a lookup of the service
            // without the roles, which will cause the service proxy with the roles being registered
            triggerProxyCreation(context, filter);
        }

        if (servicesFilter == null) {
            return;
        }

        if (myBundleContext.equals(context) || context.getBundle().getBundleId() == 0) {
            // don't hide anything from this bundle or the system bundle
            return;
        }

        for (Iterator<ServiceReference<?>> i = references.iterator(); i.hasNext(); ) {
            ServiceReference<?> sr = i.next();

            if (!servicesFilter.match(sr)) {
                continue;
            }

            if (!guardProxyCatalog.isProxyFor(sr, context)) {
                i.remove();

                // TODO this can be done in a separate thread...
                try {
                    guardProxyCatalog.proxyIfNotAlreadyProxied(sr, context);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }

    private void triggerProxyCreation(final BundleContext context, final String filter) {
        // TODO this can be done in a separate thread
        String newFilter = GUARD_ROLES_CONDITION.matcher(filter).replaceAll("(service.id=*)"); // Replace with some dummy condition that will always succeed

        boolean newTracker;
        MultiplexingServiceTracker mst;
        synchronized (trackers) {
            mst = trackers.get(newFilter);
            if (mst == null) {
                try {
                    mst = new MultiplexingServiceTracker(myBundleContext, context, newFilter);
                    trackers.put(newFilter, mst);
                    newTracker = true;
                } catch (InvalidSyntaxException e) {
                    throw new RuntimeException(e);
                }
            } else {
                newTracker = false;
            }
        }

        if (newTracker) {
            mst.open(true);
        } else {
            mst.addBundleContext(context);
        }
    }

    protected void proxyForClient(ServiceReference<?> reference, BundleContext context) {
        if (guardProxyCatalog.isProxy(reference)) {
            // It's already a proxy, we don't re-proxy
            return;
        }

        try {
            guardProxyCatalog.proxyIfNotAlreadyProxied(reference, context);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private class MultiplexingServiceTracker extends ServiceTracker<Object, Object> {
        private List<BundleContext> bundleContexts = new CopyOnWriteArrayList<BundleContext>();

        MultiplexingServiceTracker(BundleContext context, BundleContext clientContext, String filter) throws InvalidSyntaxException {
            super(context, context.createFilter(filter), null);
            addBundleContext(clientContext);
        }

        void addBundleContext(BundleContext bc) {
            if (bc.equals(myBundleContext)) {
                // don't proxy anything for myself
                return;
            }
            bundleContexts.add(bc);
        }

        void removeBundleContext(BundleContext bc) {
            bundleContexts.remove(bc);
        }

        @Override
        public Object addingService(ServiceReference<Object> reference) {
            // So there is a new service that matches the filter.
            // We now need to make sure that there is are matching proxies for it too
            // to that all the interested clients can see it...
            int i=0;
            for (BundleContext bc : bundleContexts) {
                proxyForClient(reference, bc);
            }
            return super.addingService(reference);
        }
    }
}
