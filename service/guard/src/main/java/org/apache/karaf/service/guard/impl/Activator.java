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
package org.apache.karaf.service.guard.impl;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.hooks.service.EventListenerHook;
import org.osgi.framework.hooks.service.FindHook;

public class Activator implements BundleActivator {
    private GuardProxyCatalog guardProxyCatalog;

    @Override
    public void start(BundleContext context) throws Exception {
        System.out.println("*** Activating Service Guard");
        guardProxyCatalog = new GuardProxyCatalog(context);

        context.registerService(EventListenerHook.class, new GuardingEventHook(context, guardProxyCatalog), null);
        context.registerService(FindHook.class, new GuardingFindHook(context, guardProxyCatalog), null);
    }

    @Override
    public void stop(BundleContext context) throws Exception {
        guardProxyCatalog.close();
    }
}
