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
import java.util.Map;
import java.util.Map.Entry;

import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceEvent;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.hooks.service.EventListenerHook;
import org.osgi.framework.hooks.service.ListenerHook.ListenerInfo;

public class SecuringEventHook implements EventListenerHook {
    private CommandProxyCatalog commandProxyCatalog;

    public void setCommandProxyCatalog(CommandProxyCatalog cpc) {
        commandProxyCatalog = cpc;
        /* */ System.out.println("+++ Set CPC: " + cpc);
    }

    @Override
    public void event(ServiceEvent event, Map<BundleContext, Collection<ListenerInfo>> listeners) {
        ServiceReference<?> sr = event.getServiceReference();

        if (sr.getProperty("osgi.command.function") != null && !commandProxyCatalog.isProxy(sr)) {
            for (Iterator<Map.Entry<BundleContext, Collection<ListenerInfo>>> i = listeners.entrySet().iterator(); i.hasNext(); ) {
                Entry<BundleContext, Collection<ListenerInfo>> entry = i.next();
                if (entry.getKey().getBundle().getBundleId() == 0) {
                    // don't hide anything from the system bundle
                    continue;
                }

                // hide the service from other bundles
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
