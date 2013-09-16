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
import java.util.Dictionary;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import org.apache.felix.service.command.CommandProcessor;
import org.osgi.framework.Constants;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;
import org.osgi.service.cm.ConfigurationEvent;
import org.osgi.service.cm.ConfigurationListener;

public class SecuredCommandConfigTransformer implements ConfigurationListener {
    static final String PROXY_COMMAND_ACL_PID_PREFIX = "org.apache.karaf.command.acl.";

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

        String scopeName = config.getPid().substring(PROXY_COMMAND_ACL_PID_PREFIX.length());
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

            // Put rules on the map twice, once for commands that 'execute' (implement Function) and
            // once for commands that are invoked directly.
            Object roleString = config.getProperties().get(key);
            map.put("execute" + arguments, roleString);
            map.put(key, roleString);
            map.put("*", "*"); // Any other method may be invoked by anyone
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
        sb.append("[/.*/,"); // Add a wildcard argument since the Function execute method has the arguments as second arg
        sb.append(commandACLArgs.substring(1));
        return sb.toString();
    }

    @Override
    public void configurationEvent(ConfigurationEvent event) {
        System.out.println("### Received Configuration Event: " + event.getPid());
        // TODO update generated configuration
    }
}
