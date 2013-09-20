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
package org.apache.karaf.service.guard.tools;

import java.util.Collection;
import java.util.Iterator;
import java.util.Map;

import org.osgi.framework.BundleContext;
import org.osgi.framework.Filter;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceEvent;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.hooks.service.EventListenerHook;
import org.osgi.framework.hooks.service.FindHook;
import org.osgi.framework.hooks.service.ListenerHook.ListenerInfo;

public abstract class ServiceProxyUtil {
    private final BundleContext bundleContext;
    private final Filter servicesFilter;

    /**
     * A utility class to make is easy to create Service Proxies that can add functionality/intercept
     * OSGi service invocations.
     * @param bc The BundleContext of the bundle that handles the proxification. This bundle
     * will always see both the original services as well as the proxies.
     * @param filter The filter that candidate services need to match.
     * @throws InvalidSyntaxException
     */
    public ServiceProxyUtil(BundleContext bc, String filter) throws InvalidSyntaxException {
        bundleContext = bc;
        servicesFilter = bc.createFilter(filter);

        bc.registerService(FindHook.class, new ServiceProxyFindHook(), null);
        bc.registerService(EventListenerHook.class, new ServiceProxyEventHook(), null);
    }

    public void close() {}

    /**
     * In here the decision is made whether or not a proxy for the given service will
     * be created or not. The implementation can also do the actual proxy creation in this
     * method. Normally the service proxy will be a Service Factory.
     * @param sr The service reference that can be proxied.
     * @return Whether or not to hide this service reference from clients.
     */
    abstract protected boolean proxyService(ServiceReference<?> sr, BundleContext client);

    protected void handleEvent(ServiceEvent event, Map<BundleContext, Collection<ListenerInfo>> listeners) {
        ServiceReference<?> sr = event.getServiceReference();
        if (!servicesFilter.match(sr)) {
            return;
        }

        for (Iterator<BundleContext> i = listeners.keySet().iterator(); i.hasNext(); ) {
            BundleContext bc = i.next();
            if (bundleContext.equals(bc) || bc.getBundle().getBundleId() == 0) {
                // don't hide anything from this bundle or the system bundle
                continue;
            }
            if (proxyService(sr, bc)) {
                i.remove();
            }
        }
    }

    protected void handleFind(BundleContext context, String name, String filter, boolean allServices,
            Collection<ServiceReference<?>> references) {

        if (bundleContext.equals(context) || context.getBundle().getBundleId() == 0) {
            // don't hide anything from this bundle or the system bundle
            return;
        }

        for (Iterator<ServiceReference<?>> i = references.iterator(); i.hasNext(); ) {
            ServiceReference<?> sr = i.next();

            if (!servicesFilter.match(sr)) {
                continue;
            }

            if (proxyService(sr, context)) {
                i.remove();
            }
        }
    }

    class ServiceProxyEventHook implements EventListenerHook {
        @Override
        public void event(ServiceEvent event, Map<BundleContext, Collection<ListenerInfo>> listeners) {
            handleEvent(event, listeners);
        }
    }

    class ServiceProxyFindHook implements FindHook {
        @Override
        public void find(BundleContext context, String name, String filter, boolean allServices,
                Collection<ServiceReference<?>> references) {
            handleFind(context, name, filter, allServices, references);
       }
    }
}