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

import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.management.MBeanServer;
import javax.management.ObjectName;
import javax.management.openmbean.CompositeData;
import javax.management.openmbean.TabularData;

import junit.framework.TestCase;

import org.apache.karaf.management.KarafMBeanServerGuard;
import org.apache.karaf.management.boot.KarafMBeanServerBuilder;
import org.easymock.EasyMock;

public class SecurityMBeanImplTestCase extends TestCase {
    public void testMBeanServerAccessors() throws Exception {
        MBeanServer mbs = EasyMock.createMock(MBeanServer.class);
        EasyMock.replay(mbs);

        SecurityMBeanImpl mb = new SecurityMBeanImpl();
        mb.setMBeanServer(mbs);
        assertSame(mbs, mb.getMBeanServer());
    }

    public void testCanInvokeMBean() throws Exception {
        InvocationHandler prevGuard = KarafMBeanServerBuilder.getGuard();
        try {
            MBeanServer mbs = EasyMock.createMock(MBeanServer.class);
            EasyMock.replay(mbs);

            String objectName = "foo.bar.testing:type=SomeMBean";
            KarafMBeanServerGuard testGuard = EasyMock.createMock(KarafMBeanServerGuard.class);
            EasyMock.expect(testGuard.canInvoke(mbs, new ObjectName(objectName))).andReturn(true);
            EasyMock.replay(testGuard);
            KarafMBeanServerBuilder.setGuard(testGuard);

            SecurityMBeanImpl mb = new SecurityMBeanImpl();
            mb.setMBeanServer(mbs);
            assertTrue(mb.canInvoke(objectName));
        } finally {
            KarafMBeanServerBuilder.setGuard(prevGuard);
        }
    }

    public void testCanInvokeMBean2() throws Exception {
        InvocationHandler prevGuard = KarafMBeanServerBuilder.getGuard();
        try {
            MBeanServer mbs = EasyMock.createMock(MBeanServer.class);
            EasyMock.replay(mbs);

            String objectName = "foo.bar.testing:type=SomeMBean";
            KarafMBeanServerGuard testGuard = EasyMock.createMock(KarafMBeanServerGuard.class);
            EasyMock.expect(testGuard.canInvoke(mbs, new ObjectName(objectName))).andReturn(false);
            EasyMock.replay(testGuard);
            KarafMBeanServerBuilder.setGuard(testGuard);

            SecurityMBeanImpl mb = new SecurityMBeanImpl();
            mb.setMBeanServer(mbs);
            assertFalse(mb.canInvoke(objectName));
        } finally {
            KarafMBeanServerBuilder.setGuard(prevGuard);
        }
    }

    public void testCanInvokeMBean3() throws Exception {
        InvocationHandler prevGuard = KarafMBeanServerBuilder.getGuard();
        try {
            MBeanServer mbs = EasyMock.createMock(MBeanServer.class);
            EasyMock.replay(mbs);

            String objectName = "foo.bar.testing:type=SomeMBean";
            KarafMBeanServerGuard testGuard = EasyMock.createMock(KarafMBeanServerGuard.class);
            EasyMock.expect(testGuard.canInvoke(mbs, new ObjectName(objectName))).andThrow(new IOException());
            EasyMock.replay(testGuard);
            KarafMBeanServerBuilder.setGuard(testGuard);

            SecurityMBeanImpl mb = new SecurityMBeanImpl();
            mb.setMBeanServer(mbs);
            assertFalse(mb.canInvoke(objectName));
        } finally {
            KarafMBeanServerBuilder.setGuard(prevGuard);
        }
    }

    public void testCanInvokeMBeanNoGuard() throws Exception {
        InvocationHandler prevGuard = KarafMBeanServerBuilder.getGuard();
        try {
            SecurityMBeanImpl mb = new SecurityMBeanImpl();
            assertTrue(mb.canInvoke("foo.bar.testing:type=SomeMBean"));
        } finally {
            KarafMBeanServerBuilder.setGuard(prevGuard);
        }
    }

    public void testCanInvokeMethod() throws Exception {
        InvocationHandler prevGuard = KarafMBeanServerBuilder.getGuard();
        try {
            MBeanServer mbs = EasyMock.createMock(MBeanServer.class);
            EasyMock.replay(mbs);

            String objectName = "foo.bar.testing:type=SomeMBean";
            KarafMBeanServerGuard testGuard = EasyMock.createMock(KarafMBeanServerGuard.class);
            String[] la = new String [] {"long"};
            String[] sa = new String [] {"java.lang.String"};
            String[] sa2 = new String [] {"java.lang.String", "java.lang.String"};
            EasyMock.expect(testGuard.canInvoke(mbs, new ObjectName(objectName), "testMethod", la)).andReturn(true);
            EasyMock.expect(testGuard.canInvoke(mbs, new ObjectName(objectName), "testMethod", sa)).andReturn(true);
            EasyMock.expect(testGuard.canInvoke(mbs, new ObjectName(objectName), "otherMethod", sa2)).andReturn(false);
            EasyMock.replay(testGuard);
            KarafMBeanServerBuilder.setGuard(testGuard);

            SecurityMBeanImpl mb = new SecurityMBeanImpl();
            mb.setMBeanServer(mbs);
            assertTrue(mb.canInvoke(objectName, "testMethod", la));
            assertTrue(mb.canInvoke(objectName, "testMethod", sa));
            assertFalse(mb.canInvoke(objectName, "otherMethod", sa2));
        } finally {
            KarafMBeanServerBuilder.setGuard(prevGuard);
        }
    }

    public void testCanInvokeMethodException() throws Exception {
        InvocationHandler prevGuard = KarafMBeanServerBuilder.getGuard();
        try {
            MBeanServer mbs = EasyMock.createMock(MBeanServer.class);
            EasyMock.replay(mbs);

            String objectName = "foo.bar.testing:type=SomeMBean";
            KarafMBeanServerGuard testGuard = EasyMock.createMock(KarafMBeanServerGuard.class);
            String[] ea = new String [] {};
            EasyMock.expect(testGuard.canInvoke(mbs, new ObjectName(objectName), "testMethod", ea)).andThrow(new IOException());
            EasyMock.replay(testGuard);
            KarafMBeanServerBuilder.setGuard(testGuard);

            SecurityMBeanImpl mb = new SecurityMBeanImpl();
            mb.setMBeanServer(mbs);
            assertFalse(mb.canInvoke(objectName, "testMethod", ea));
        } finally {
            KarafMBeanServerBuilder.setGuard(prevGuard);
        }
    }

    public void testCanInvokeMethodNoGuard() throws Exception {
        InvocationHandler prevGuard = KarafMBeanServerBuilder.getGuard();
        try {
            SecurityMBeanImpl mb = new SecurityMBeanImpl();
            assertTrue(mb.canInvoke("foo.bar.testing:type=SomeMBean", "someMethod", new String [] {}));
        } finally {
            KarafMBeanServerBuilder.setGuard(prevGuard);
        }
    }

    public void testCanInvokeBulk() throws Exception {
        InvocationHandler prevGuard = KarafMBeanServerBuilder.getGuard();
        try {
            MBeanServer mbs = EasyMock.createMock(MBeanServer.class);
            EasyMock.replay(mbs);

            String objectName = "foo.bar.testing:type=SomeMBean";
            KarafMBeanServerGuard testGuard = EasyMock.createMock(KarafMBeanServerGuard.class);
            final String[] la = new String [] {"long"};
            final String[] sa = new String [] {"java.lang.String"};
            final String[] sa2 = new String [] {"java.lang.String", "java.lang.String"};
            EasyMock.expect(testGuard.canInvoke(EasyMock.eq(mbs), EasyMock.eq(new ObjectName(objectName)), EasyMock.eq("testMethod"), EasyMock.aryEq(la))).andReturn(true);
            EasyMock.expect(testGuard.canInvoke(mbs, new ObjectName(objectName), "testMethod", sa)).andReturn(true);
            EasyMock.expect(testGuard.canInvoke(mbs, new ObjectName(objectName), "otherMethod", sa2)).andReturn(false);
            EasyMock.replay(testGuard);
            KarafMBeanServerBuilder.setGuard(testGuard);

            SecurityMBeanImpl mb = new SecurityMBeanImpl();
            mb.setMBeanServer(mbs);
            Map<String, List<String>> query = new HashMap<String, List<String>>();
            query.put(objectName, Arrays.asList("testMethod(long)"));
            TabularData result = mb.canInvoke(query);
            assertEquals(1, result.size());

            CompositeData cd = result.get(new Object [] {objectName, "testMethod(long)"});
            assertEquals(objectName, cd.get("ObjectName"));
            assertEquals("testMethod(long)", cd.get("Method"));
            assertEquals(true, cd.get("CanInvoke"));
        } finally {
            KarafMBeanServerBuilder.setGuard(prevGuard);
        }
    }
}
