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
package org.apache.karaf.management;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.management.ObjectName;

import org.apache.karaf.jaas.boot.KarafMBeanServerBuilder;
import org.osgi.service.cm.ConfigurationAdmin;

public class KarafMBeanServerGuard implements InvocationHandler {
    // TODO this is duplicated from KarafMBeanServerBuilder
    private static final List<String> guarded = Collections.unmodifiableList(Arrays.asList(
            "invoke", "getAttribute", "getAttributes", "setAttribute", "setAttributes"));
    private ConfigurationAdmin configAdmin;

    public void setConfigAdminService(ConfigurationAdmin ca) {
        configAdmin = ca;
    }

    public void init() {
        System.out.println("**** Initializing guard...");
        KarafMBeanServerBuilder.init(this);
    }

    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        if (guarded.contains(method.getName())) {
            if (((ObjectName) args[0]).getCanonicalName().startsWith("org.apache.karaf")) {
                System.out.println("**** Guard being invoked:" + method.getName() + "#" + Arrays.toString(args));
                System.out.println("     Looking in CM: " + configAdmin);


            }
        }

        return null;
    }

}
