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

public class CommandProxyCatalog {
    public static final String PROXY_COMMAND_ROLES_PROPERTY = "org.apache.karaf.command.roles";

    private final ConcurrentMap<ServiceReference<?>, ServiceRegistrationHolder> proxyMap =
            new ConcurrentHashMap<ServiceReference<?>, ServiceRegistrationHolder>();
    private ConfigurationAdmin configAdmin;

    public void setConfigAdmin(ConfigurationAdmin configAdmin) {
        this.configAdmin = configAdmin;
    }

    boolean isProxy(ServiceReference<?> sr) {
        return sr.getProperty(PROXY_COMMAND_ROLES_PROPERTY) != null;
    }

    void proxy(ServiceReference<?> originalRef) throws Exception {
        if (proxyMap.containsKey(originalRef)) {
            return;
        }
        if (isProxy(originalRef)) {
            return;
        }

        Dictionary<String, Object> props = proxyProperties(originalRef);
        // /* */ System.out.println("@@@ Proxying: " + props);
        BundleContext context = originalRef.getBundle().getBundleContext();

        // make sure it's on the map before the proxy is registered, as that can trigger
        // another call into this method, and we need to make sure that it doesn't proxy
        // the service again.
        ServiceRegistrationHolder registrationHolder = new ServiceRegistrationHolder();
        proxyMap.put(originalRef, registrationHolder);

        ServiceRegistration<?> proxyReg = context.registerService((String[]) originalRef.getProperty(Constants.OBJECTCLASS),
                context.getService(originalRef), props);

        // put the actual service registration in the holder
        registrationHolder.registration = proxyReg;

        // TODO register listener that unregisters the proxy once the original service is gone.
        // Note that this listener must be registered under the bundlecontext of the system bundle
        // otherwise we won't get notified!
    }

    private Dictionary<String, Object> proxyProperties(ServiceReference<?> sr) throws Exception {
        Dictionary<String, Object> p = new Hashtable<String, Object>();

        for (String key : sr.getPropertyKeys()) {
            p.put(key, sr.getProperty(key));
        }
        List<String> roles = getRoles(sr);
        p.put(PROXY_COMMAND_ROLES_PROPERTY, roles);
        return p;
    }

    private List<String> getRoles(ServiceReference<?> sr) throws Exception {
        String scope = "" + sr.getProperty("osgi.command.scope");
        String function = "" + sr.getProperty("osgi.command.function");
        if (scope == null || function == null)
            return Collections.emptyList();

        if (scope.trim().equals("*")) {
            scope = "xxglobalxx"; // TODO what to do here?
        }

        Configuration[] configs = configAdmin.listConfigurations("(service.pid=" + PROXY_COMMAND_ROLES_PROPERTY + "." + scope + ")");
        if (configs == null)
            return Collections.emptyList();

        for (Configuration c : configs) {
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

    private static class ServiceRegistrationHolder {
        ServiceRegistration<?> registration;
    }
}
