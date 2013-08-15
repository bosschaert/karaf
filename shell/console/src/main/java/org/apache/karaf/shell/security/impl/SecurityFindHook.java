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

import java.util.Collection;
import java.util.Iterator;

import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.hooks.service.FindHook;

public class SecurityFindHook implements FindHook {
    private CommandProxyCatalog commandProxyCatalog;

    public void setCommandProxyCatalog(CommandProxyCatalog cpc) {
        commandProxyCatalog = cpc;
        /* */ System.out.println("### Set CPC: " + cpc);
    }

    @Override
    public void find(BundleContext context, String name, String filter, boolean allServices,
            Collection<ServiceReference<?>> references) {
        if (context.getBundle().getBundleId() == 0) {
            // don't hide anything from the system bundle
            return;
        }

        for (Iterator<ServiceReference<?>> i = references.iterator(); i.hasNext(); ) {
            ServiceReference<?> sr = i.next();
            if (sr.getProperty("osgi.command.function") != null && !commandProxyCatalog.isProxy(sr)) {
                try {
                    commandProxyCatalog.proxy(sr);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                i.remove();
            }
        }
    }
}
