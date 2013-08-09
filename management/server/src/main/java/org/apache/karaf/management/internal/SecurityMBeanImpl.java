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
package org.apache.karaf.management.internal;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.management.MBeanServer;
import javax.management.NotCompliantMBeanException;
import javax.management.ObjectName;
import javax.management.StandardMBean;
import javax.management.openmbean.CompositeData;
import javax.management.openmbean.CompositeDataSupport;
import javax.management.openmbean.CompositeType;
import javax.management.openmbean.OpenType;
import javax.management.openmbean.SimpleType;
import javax.management.openmbean.TabularData;
import javax.management.openmbean.TabularDataSupport;
import javax.management.openmbean.TabularType;

import org.apache.karaf.management.KarafMBeanServerGuard;
import org.apache.karaf.management.SecurityMBean;
import org.apache.karaf.management.boot.KarafMBeanServerBuilder;

public class SecurityMBeanImpl extends StandardMBean implements SecurityMBean {
    private MBeanServer mbeanServer;

    public SecurityMBeanImpl() throws NotCompliantMBeanException {
        super(SecurityMBean.class);
    }

    public boolean canInvoke(String objectName) throws Exception {
        KarafMBeanServerGuard guard = (KarafMBeanServerGuard) KarafMBeanServerBuilder.getGuard();
        if (guard == null)
            return true;

        return guard.canInvoke(mbeanServer, new ObjectName(objectName));
    }

    public boolean canInvoke(String objectName, String methodName, String[] argumentTypes) throws Exception {
        ObjectName on = new ObjectName(objectName);

        KarafMBeanServerGuard guard = (KarafMBeanServerGuard) KarafMBeanServerBuilder.getGuard();
        if (guard == null)
            return true;

        return guard.canInvoke(mbeanServer, on, methodName, argumentTypes);
    }

    public TabularData canInvoke(Map<String, List<String>> bulkQuery) throws Exception {
        // TODO convert to constant
        CompositeType resultType = new CompositeType("CanInvokeBulkResult",
                "Result of the canInvoke bulk operation",
                new String [] {"ObjectName", "Method", "CanInvoke"}, // TODO convert to constant
                new String [] {"The ObjectName of the MBean to check",
                "The Method to check. This can either be a bare method name which means 'any method with this name' or a specific overload such as foo(java.lang.String). If empty this means 'any' method.",
                "true if the method or mbean can potentially be invoked by the current user"},
                new OpenType[] {SimpleType.STRING, SimpleType.STRING, SimpleType.BOOLEAN});

        // TODO convert to constant
        TabularType tableType = new TabularType("CanInvokeResults", "Result of canInvoke() bulk operation", resultType,
                new String [] {"ObjectName", "Method"});
        TabularData table = new TabularDataSupport(tableType);

        System.out.println("*** canInvoke: " + bulkQuery);
        for (Map.Entry<String, List<String>> entry : bulkQuery.entrySet()) {
            System.out.println("  " + entry.getKey() + "#" + entry.getValue() + "#" + entry.getValue().size());

            String objectName = entry.getKey();
            List<String> methods = entry.getValue();
            if (methods.size() == 0) {
                boolean res = canInvoke(objectName);
                CompositeData data = new CompositeDataSupport(resultType,
                        new String [] {"ObjectName", "Method", "CanInvoke"}, // TODO from constant
                        new Object [] {objectName, "", res});
                table.put(data);
            } else {
                for (String method : methods) {
                    List<String> argTypes = new ArrayList<String>();
                    String name = parseMethodName(method, argTypes);
                    boolean res = canInvoke(objectName, name, argTypes.toArray(new String [] {}));
                    CompositeData data = new CompositeDataSupport(resultType,
                            new String [] {"ObjectName", "Method", "CanInvoke"},
                            new Object [] {objectName, method, res});
                    table.put(data);
                }
            }
        }

        return table;
    }

    private String parseMethodName(String method, List<String> argTypes) {
        method = method.trim();
        int idx = method.indexOf('(');
        if (idx < 0)
            return method;

        String args = method.substring(idx + 1, method.length() - 1);
        for (String arg : args.split(",")) {
            argTypes.add(arg);
        }
        return method.substring(0, idx);
    }

    public MBeanServer getMBeanServer() {
        return this.mbeanServer;
    }

    public void setMBeanServer(MBeanServer mbeanServer) {
        this.mbeanServer = mbeanServer;
    }
}
