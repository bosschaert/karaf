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
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceEvent;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.hooks.service.EventListenerHook;
import org.osgi.framework.hooks.service.ListenerHook.ListenerInfo;

public class SecuringEventHook implements EventListenerHook {
    private final BundleContext myBundleContext;

    SecuringEventHook(BundleContext myBC) {
        myBundleContext = myBC;
    }

    @Override
    public void event(ServiceEvent event, Map<BundleContext, Collection<ListenerInfo>> listeners) {
        ServiceReference<?> sr = event.getServiceReference();

        if (Activator.getStringPlusProperty(sr.getProperty(Constants.OBJECTCLASS)).contains("testservice.api.TestServiceAPI")) {
            System.out.println("Found: " + sr);

            for (Iterator<Map.Entry<BundleContext, Collection<ListenerInfo>>> i = listeners.entrySet().iterator(); i.hasNext(); ) {
                Entry<BundleContext, Collection<ListenerInfo>> entry = i.next();
                if (myBundleContext.equals(entry.getKey()) || entry.getKey().getBundle().getBundleId() == 0) {
                    // don't hide anything from me nor the system bundle
                    continue;
                }
                // hide the service from other bundles
                System.out.println("Removing from: " + entry.getKey().getBundle().getSymbolicName() + "(" + parseValue(entry.getValue()) + ")");
                i.remove();
            }
        }
    }

    private String parseValue(Collection<ListenerInfo> value) {
        StringBuilder sb = new StringBuilder();
        for (ListenerInfo li : value) {
            if (sb.length() != 0)
                sb.append(',');

            sb.append(li.getFilter());
        }
        return sb.toString();
    }
}
