/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.karaf.shell.console.impl.jline;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.security.PrivilegedAction;

import javax.security.auth.Subject;

import org.apache.felix.gogo.api.CommandSessionListener;
import org.apache.felix.service.command.CommandProcessor;
import org.apache.felix.service.command.Converter;
import org.apache.karaf.jaas.boot.principal.RolePrincipal;
import org.apache.karaf.shell.console.impl.jline.ConsoleImpl.DelegateSession;
import org.apache.karaf.shell.security.impl.SecuredCommandProcessorImpl;
import org.easymock.EasyMock;
import org.easymock.IAnswer;
import org.junit.Test;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Filter;
import org.osgi.framework.FrameworkUtil;
import org.osgi.framework.ServiceListener;
import org.osgi.framework.ServiceReference;

public class ConsoleImplTest {
    @Test
    public void testConsoleImpl() throws Exception {
        ServiceReference<?> cmRef = EasyMock.createMock(ServiceReference.class);
        EasyMock.expect(cmRef.getProperty(CommandProcessor.COMMAND_SCOPE)).andReturn("myscope").anyTimes();
        EasyMock.expect(cmRef.getProperty(CommandProcessor.COMMAND_FUNCTION)).andReturn("myfunction").anyTimes();
        EasyMock.replay(cmRef);
        ServiceReference<?>[] cmRefs = new ServiceReference[] {cmRef};

        BundleContext bc = EasyMock.createMock(BundleContext.class);
        EasyMock.expect(bc.getServiceReference((Class<?>) EasyMock.anyObject())).andReturn(null).anyTimes();
        EasyMock.expect(bc.getService((ServiceReference<?>) EasyMock.anyObject())).andReturn(null).anyTimes();
        bc.addServiceListener(EasyMock.isA(ServiceListener.class), EasyMock.isA(String.class));
        EasyMock.expectLastCall().anyTimes();
        EasyMock.expect(bc.getServiceReferences((String) null,
                "(&(osgi.command.scope=*)(osgi.command.function=*)" +
                "(|(org.apache.karaf.service.guard.roles=myrole)(!(org.apache.karaf.service.guard.roles=*))))")).andReturn(cmRefs).anyTimes();
        EasyMock.expect(bc.getServiceReferences(Converter.class.getName(), null)).andReturn(null).anyTimes();
        EasyMock.expect(bc.getServiceReferences(CommandSessionListener.class.getName(), null)).andReturn(null).anyTimes();
        EasyMock.expect(bc.createFilter(EasyMock.isA(String.class))).andAnswer(new IAnswer<Filter>() {
            @Override
            public Filter answer() throws Throwable {
                return FrameworkUtil.createFilter((String) EasyMock.getCurrentArguments()[0]);
            }
        }).anyTimes();
        EasyMock.replay(bc);

        final ConsoleImpl console = new ConsoleImpl(null, System.in, System.out, System.err, null, "UTF-8", null, bc);
        assertTrue(console.session instanceof DelegateSession);

        console.session.put("foo", "bar");

        final DelegateSession ds = (DelegateSession) console.session;
        assertNull("Precondition", ds.delegate);

        Subject subject = new Subject();
        subject.getPrincipals().add(new RolePrincipal("myrole"));

        Subject.doAs(subject, new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                SecuredCommandProcessorImpl secCP = console.createSecuredCommandProcessor();
                assertNotNull(ds.delegate);
                assertEquals("Attributes set before the delegate was set should have been transferred",
                        "bar", ds.get("foo"));
                assertEquals("Attributes set before the delegate was set should have been transferred",
                        "bar", ds.delegate.get("foo"));
                assertSame(System.out, ds.delegate.getConsole());
                assertSame(System.out, ds.getConsole());

                assertTrue(secCP.getCommands().contains("myscope:myfunction"));

                return null;
            }
        });
    }
}
