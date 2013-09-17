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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.PrivilegedAction;
import java.util.Map;

import javax.security.auth.Subject;

import org.apache.felix.gogo.api.CommandSessionListener;
import org.apache.felix.service.command.Converter;
import org.apache.felix.service.threadio.ThreadIO;
import org.apache.karaf.jaas.boot.principal.RolePrincipal;
import org.easymock.EasyMock;
import org.easymock.IAnswer;
import org.junit.Test;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Filter;
import org.osgi.framework.FrameworkUtil;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceListener;
import org.osgi.framework.ServiceReference;

public class SecuredCommandProcessorImplTest {
    @Test
    public void testCommandProcessor() throws Exception {
        ThreadIO tio = EasyMock.createMock(ThreadIO.class);
        EasyMock.replay(tio);

        @SuppressWarnings("unchecked")
        ServiceReference<ThreadIO> tioRef = EasyMock.createMock(ServiceReference.class);
        EasyMock.replay(tioRef);

        final BundleContext bc = EasyMock.createMock(BundleContext.class);
        EasyMock.expect(bc.getServiceReference(ThreadIO.class)).andReturn(tioRef).anyTimes();
        EasyMock.expect(bc.getService(tioRef)).andReturn(tio).anyTimes();
        EasyMock.expect(bc.createFilter(EasyMock.isA(String.class))).andAnswer(new IAnswer<Filter>() {
            @Override
            public Filter answer() throws Throwable {
                return FrameworkUtil.createFilter((String) EasyMock.getCurrentArguments()[0]);
            }
        }).anyTimes();
        EasyMock.expect(bc.getServiceReferences((String) EasyMock.anyObject(), (String) EasyMock.anyObject())).andReturn(null).anyTimes();
        // Here are the expected calls
        expectServiceTracker(bc,
                "(&(osgi.command.scope=*)(osgi.command.function=*)" +
                "(|(org.apache.karaf.service.guard.roles=aaabbbccc)(!(org.apache.karaf.service.guard.roles=*))))");
        expectServiceTracker(bc, "(objectClass=" + Converter.class.getName() + ")");
        expectServiceTracker(bc, "(objectClass=" + CommandSessionListener.class.getName() + ")");
        EasyMock.replay(bc);

        Subject subject = new Subject();
        subject.getPrincipals().add(new RolePrincipal("aaabbbccc"));

        Subject.doAs(subject, new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                MySecuredCommandProcessorImpl scp = new MySecuredCommandProcessorImpl(bc) {};

                assertEquals(3, scp.getCommands().size());
                assertTrue(scp.getCommands().contains("osgi:addcommand"));
                assertTrue(scp.getCommands().contains("osgi:removecommand"));
                assertTrue(scp.getCommands().contains("osgi:eval"));
                assertEquals(1, scp.getConstants().size());
                assertEquals(bc, scp.getConstants().get(".context"));
                return null;
            }
        });
    }

    void expectServiceTracker(final BundleContext bc, String expectedFilter) throws InvalidSyntaxException {
        bc.addServiceListener(EasyMock.isA(ServiceListener.class), EasyMock.eq(expectedFilter));
        EasyMock.expectLastCall().once();
        // not checking this one...
    }

    // Subclass to provide access to some protected members
    static class MySecuredCommandProcessorImpl extends SecuredCommandProcessorImpl {
        public MySecuredCommandProcessorImpl(BundleContext bc) {
            super(bc);
        }

        Map<String, Object> getConstants() {
            return constants;
        }
    };
}
