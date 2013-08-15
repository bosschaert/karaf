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
package org.apache.karaf.shell.security.impl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;
import org.osgi.util.tracker.ServiceTracker;

class CommandProxyCatalog {
    private static final String PROXY_IDENTIFICATION_PROPERTY = ".Karaf-Proxied"; // TODO can we remove this?
    private static final String PROXY_COMMAND_ROLES_PROPERTY = "org.apache.karaf.command.roles";

    private final ConcurrentMap<ServiceReference<?>, ServiceReference<?>> proxyMap =
            new ConcurrentHashMap<ServiceReference<?>, ServiceReference<?>>();
    private final ServiceTracker<ConfigurationAdmin, ConfigurationAdmin> configAdminTracker;

    public CommandProxyCatalog(BundleContext bc) {
        // TODO turn into a blueprint component...
        configAdminTracker = new ServiceTracker<ConfigurationAdmin, ConfigurationAdmin>(bc, ConfigurationAdmin.class, null);
        configAdminTracker.open();
    }

    boolean isProxy(ServiceReference<?> sr) {
        return sr.getProperty(PROXY_IDENTIFICATION_PROPERTY) != null;
    }

    void proxy(ServiceReference<?> originalRef) throws Exception {
        if (proxyMap.containsKey(originalRef)) {
            // alreadyProxied.
            return;
        }

        Dictionary<String, Object> props = proxyProperties(originalRef);
        /* */ System.out.println("@@@ Proxying: " + props);
        BundleContext context = originalRef.getBundle().getBundleContext();
        ServiceRegistration<?> proxyReg = context.registerService((String[]) originalRef.getProperty(Constants.OBJECTCLASS),
                context.getService(originalRef), props);
        proxyMap.put(originalRef, proxyReg.getReference());

        // TODO register listener that unregisters the proxy once the original service is gone.
    }

    private Dictionary<String, Object> proxyProperties(ServiceReference<?> sr) throws Exception {
        Dictionary<String, Object> p = new Hashtable<String, Object>();

        for (String key : sr.getPropertyKeys()) {
            p.put(key, sr.getProperty(key));
        }
        List<String> roles = getRoles(sr);
        p.put(PROXY_COMMAND_ROLES_PROPERTY, roles);
        p.put(PROXY_IDENTIFICATION_PROPERTY, true);
        return p;
    }

    private List<String> getRoles(ServiceReference<?> sr) throws Exception {
        String scope = "" + sr.getProperty("osgi.command.scope");
        String function = "" + sr.getProperty("osgi.command.function");
        ConfigurationAdmin ca = configAdminTracker.getService();
        if (ca == null)
            return null;
        for (Configuration c : ca.listConfigurations("service.pid=" + PROXY_COMMAND_ROLES_PROPERTY + "." + scope)) {
            List<String> l = new ArrayList<String>();
            Object roles = c.getProperties().get(function);
            if (roles instanceof String) {
                for (String r : ((String) roles).split(",")) {
                    l.add(r.trim());
                }
            }
            return l;
        }
        return Collections.emptyList();
    }
}
