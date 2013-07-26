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
package org.apache.karaf.management.mbeans.security.internal;

import javax.management.MBeanServer;
import javax.management.MalformedObjectNameException;
import javax.management.NotCompliantMBeanException;
import javax.management.ObjectName;
import javax.management.StandardMBean;

import org.apache.karaf.management.KarafMBeanServerGuard;
import org.apache.karaf.management.boot.KarafMBeanServerBuilder;
import org.apache.karaf.management.mbeans.security.SecurityMBean;

public class SecurityMBeanImpl extends StandardMBean implements SecurityMBean {
    private MBeanServer mbeanServer;

    public SecurityMBeanImpl() throws NotCompliantMBeanException {
        super(SecurityMBean.class);
    }

    public boolean canInvoke(String objectName) throws MalformedObjectNameException {
        KarafMBeanServerGuard guard = (KarafMBeanServerGuard) KarafMBeanServerBuilder.getGuard();
        if (guard == null)
            return true;

        try {
            return guard.canInvoke(mbeanServer, new ObjectName(objectName));
        } catch (Exception e) {
            return false;
        }
    }

    public boolean canInvoke(String objectName, String methodName, String[] argumentTypes) throws MalformedObjectNameException {
        ObjectName on = new ObjectName(objectName);

        KarafMBeanServerGuard guard = (KarafMBeanServerGuard) KarafMBeanServerBuilder.getGuard();
        if (guard == null)
            return true;

        try {
            return guard.canInvoke(mbeanServer, on, methodName, argumentTypes);
        } catch (Exception e) {
            return false;
        }
    }

    public MBeanServer getMBeanServer() {
        return this.mbeanServer;
    }

    public void setMBeanServer(MBeanServer mbeanServer) {
        this.mbeanServer = mbeanServer;
    }
}
