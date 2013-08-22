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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Dictionary;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.felix.service.command.CommandProcessor;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;
import org.osgi.service.cm.ConfigurationEvent;
import org.osgi.service.cm.ConfigurationListener;

public class CommandProxyCatalog implements ConfigurationListener {
    public static final String PROXY_COMMAND_ROLES_PROPERTY = "org.apache.karaf.command.roles";
    private static final String PROXY_COMMAND_ACL_PID_PREFIX = "org.apache.karaf.command.acl.";

    private final ConcurrentMap<ServiceReference<?>, ServiceRegistrationHolder> proxyMap =
            new ConcurrentHashMap<ServiceReference<?>, ServiceRegistrationHolder>();
    private ConfigurationAdmin configAdmin;

    public void setConfigAdmin(ConfigurationAdmin configAdmin) {
        this.configAdmin = configAdmin;
    }

    public void init() throws Exception {
        Configuration[] configs = configAdmin.listConfigurations("(" + Constants.SERVICE_PID  + "=" + PROXY_COMMAND_ACL_PID_PREFIX + "*)");
        if (configs == null)
            return;

        System.out.println("@@@ Initial Config Set:");
        for (Configuration config : configs) {
            System.out.println("  " + config.getPid());
            generateServiceGuardConfig(config);
        }
    }

    private void generateServiceGuardConfig(Configuration config) throws IOException {
        if (!config.getPid().startsWith(PROXY_COMMAND_ACL_PID_PREFIX)) {
            // Not a command scope configuration file
            return;
        }

        String scopeName = config.getPid().substring(PROXY_COMMAND_ROLES_PROPERTY.length() - 1);
        if (scopeName.indexOf('.') >= 0) {
            // Scopes don't contains dots, not a command scope
            return;
        }
        scopeName = scopeName.trim();

        Map<String, Dictionary<String, Object>> configMaps = new HashMap<String, Dictionary<String,Object>>();
        for (Enumeration<String> e = config.getProperties().keys(); e.hasMoreElements(); ) {
            String key = e.nextElement();
            String bareCommand = key;
            String arguments = "";
            int idx = bareCommand.indexOf('[');
            if (idx >= 0) {
                arguments = convertArgs(bareCommand.substring(idx));
                bareCommand = bareCommand.substring(0, idx);
            }
            if (bareCommand.indexOf('.') >= 0) {
                // Not a command
                continue;
            }
            bareCommand = bareCommand.trim();

            String pid = "org.apache.karaf.service.acl.command." + scopeName + "." + bareCommand;
            Dictionary<String, Object> map;
            if (!configMaps.containsKey(pid)) {
                map = new Hashtable<String, Object>();
                map.put("service.guard", "(&(" +
                        CommandProcessor.COMMAND_SCOPE + "=" + scopeName + ")(" +
                        CommandProcessor.COMMAND_FUNCTION + "=" + bareCommand + "))");
                configMaps.put(pid, map);
            } else {
                map = configMaps.get(pid);
            }
            map.put("execute" + arguments, config.getProperties().get(key));
        }

        // Update config admin with the generated configuration
        for (Map.Entry<String, Dictionary<String, Object>> entry : configMaps.entrySet()) {
            Configuration genConfig = configAdmin.getConfiguration(entry.getKey());
            genConfig.update(entry.getValue());
        }
    }

    private String convertArgs(String commandACLArgs) {
        if (!commandACLArgs.startsWith("[/")) {
            throw new IllegalStateException("Badly formatted argument match: " + commandACLArgs + " Should start with '[/'");
        }
        if (!commandACLArgs.endsWith("/]")) {
            throw new IllegalStateException("Badly formatted argument match: " + commandACLArgs + " Should end with '/]'");
        }
        StringBuilder sb = new StringBuilder();
        sb.append("[/.*/,"); // Add an argument since the Function execute method has the arguments as second arg
        sb.append(commandACLArgs.substring(2));
        return sb.toString();
    }

    @Override
    public void configurationEvent(ConfigurationEvent event) {
        System.out.println("### Received Configuration Event: " + event.getPid());
        // TODO update generated configuration
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

        Configuration[] configs = configAdmin.listConfigurations("(service.pid=" + PROXY_COMMAND_ACL_PID_PREFIX + scope + ")");
        if (configs == null)
            return Collections.emptyList();

        for (Configuration c : configs) {
            List<String> l = new ArrayList<String>();

            for (Enumeration<String> e = c.getProperties().keys(); e.hasMoreElements(); ) {
                String key = e.nextElement();

                String bareCommand = key;
                int idx = bareCommand.indexOf('[');
                if (idx >= 0) {
                    bareCommand = bareCommand.substring(0, idx);
                }
                if (bareCommand.trim().equals(function)) {
                    Object roles = c.getProperties().get(key);
                    if (roles instanceof String) {
                        for (String r : ((String) roles).split(",")) {
                            l.add(r.trim());
                        }
                    }
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
