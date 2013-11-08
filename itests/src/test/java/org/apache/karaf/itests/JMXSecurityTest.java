/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.karaf.itests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.ops4j.pax.exam.karaf.options.KarafDistributionOption.editConfigurationFilePut;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import javax.management.Attribute;
import javax.management.AttributeNotFoundException;
import javax.management.InstanceNotFoundException;
import javax.management.InvalidAttributeValueException;
import javax.management.MBeanException;
import javax.management.MBeanServerConnection;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
import javax.management.ReflectionException;
import javax.management.openmbean.CompositeData;
import javax.management.openmbean.TabularData;
import javax.management.remote.JMXConnector;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.Configuration;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.options.extra.VMOption;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;

@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class JMXSecurityTest extends KarafTestSupport {
    private static AtomicInteger counter = new AtomicInteger(0);

    @Configuration
    public Option[] config() {
        List<Option> options = new ArrayList<Option>(Arrays.asList(super.config()));

        // Add some extra options used by this test...
        options.addAll(Arrays.asList(
            new VMOption("-Djavax.management.builder.initial=org.apache.karaf.management.boot.KarafMBeanServerBuilder"),
            editConfigurationFilePut("etc/jmx.acl.org.apache.karaf.service.cfg", "getServices()", "admin"),
            editConfigurationFilePut("etc/jmx.acl.org.apache.karaf.service.cfg", "getServices(boolean)", "viewer"),
            editConfigurationFilePut("etc/jmx.acl.org.apache.karaf.service.cfg", "getServices(long)", "manager"),
            editConfigurationFilePut("etc/jmx.acl.org.apache.karaf.service.cfg", "getServices(long,boolean)", "admin")));
        return options.toArray(new Option[] {});
    }

    @Test
    public void testJMXSecurityAsViewer() throws Exception {
        String suffix = "_" + counter.incrementAndGet();
        String managerUser = "managerUser" + System.currentTimeMillis() + suffix;
        String managerGroup = "managerGroup" + System.currentTimeMillis() + suffix;
        String viewerUser = "viewerUser" + System.currentTimeMillis() + suffix;

        System.out.println(executeCommand("jaas:realm-manage --realm karaf" +
            ";jaas:user-add " + managerUser + " " + managerUser +
            ";jaas:group-add " + managerUser + " " + managerGroup +
            ";jaas:group-role-add " + managerGroup + " viewer" +
            ";jaas:group-role-add " + managerGroup + " manager" +
            ";jaas:user-add " + viewerUser + " " + viewerUser +
            ";jaas:role-add " + viewerUser + " viewer" +
            ";jaas:update" +
            ";jaas:realm-manage --realm karaf" +
            ";jaas:user-list"));

        JMXConnector connector = getJMXConnector(viewerUser, viewerUser);
        MBeanServerConnection connection = connector.getMBeanServerConnection();
        ObjectName systemMBean = new ObjectName("org.apache.karaf:type=system,name=root");

        assertEquals(100, connection.getAttribute(systemMBean, "StartLevel"));
        assertSetAttributeSecEx(connection, systemMBean, new Attribute("StartLevel", 101));
        assertEquals("Changing the start level should have no effect for a viewer",
               100, connection.getAttribute(systemMBean, "StartLevel"));
        assertInvokeSecEx(connection, systemMBean, "halt");

        ObjectName memoryMBean = new ObjectName("java.lang:type=Memory");
        assertEquals(false, connection.getAttribute(memoryMBean, "Verbose"));
        assertSetAttributeSecEx(connection, memoryMBean, new Attribute("Verbose", true));
        assertEquals("Changing the verbosity should have no effect for a viewer",
                false, connection.getAttribute(memoryMBean, "Verbose"));
        assertInvokeSecEx(connection, memoryMBean, "gc");

        testJMXSecurityMBean(connection, false, false);
        testKarafConfigAdminMBean(connection, false, false);
//        testOSGiConfigAdminMBean(connction, false, false);
    }

    @Test
    public void testJMXSecurityAsManager() throws Exception {
        String suffix = "_" + counter.incrementAndGet();
        String managerUser = "managerUser" + System.currentTimeMillis() + suffix;
        String managerGroup = "managerGroup" + System.currentTimeMillis() + suffix;
        String viewerUser = "viewerUser" + System.currentTimeMillis() + suffix;

        System.out.println(executeCommand("jaas:realm-manage --realm karaf" +
            ";jaas:user-add " + managerUser + " " + managerUser +
            ";jaas:group-add " + managerUser + " " + managerGroup +
            ";jaas:group-role-add " + managerGroup + " viewer" +
            ";jaas:group-role-add " + managerGroup + " manager" +
            ";jaas:user-add " + viewerUser + " " + viewerUser +
            ";jaas:role-add " + viewerUser + " viewer" +
            ";jaas:update" +
            ";jaas:realm-manage --realm karaf" +
            ";jaas:user-list"));

        JMXConnector connector = getJMXConnector(managerUser, managerUser);
        MBeanServerConnection connection = connector.getMBeanServerConnection();
        ObjectName systemMBean = new ObjectName("org.apache.karaf:type=system,name=root");

        assertEquals(100, connection.getAttribute(systemMBean, "StartLevel"));
        assertSetAttributeSecEx(connection, systemMBean, new Attribute("StartLevel", 101));
        assertEquals("Changing the start level should have no effect for a viewer",
               100, connection.getAttribute(systemMBean, "StartLevel"));
        assertInvokeSecEx(connection, systemMBean, "halt");

        ObjectName memoryMBean = new ObjectName("java.lang:type=Memory");
        assertEquals(false, connection.getAttribute(memoryMBean, "Verbose"));
        assertSetAttributeSecEx(connection, memoryMBean, new Attribute("Verbose", true));
        assertEquals("Changing the verbosity should have no effect for a viewer",
                false, connection.getAttribute(memoryMBean, "Verbose"));
        connection.invoke(memoryMBean, "gc", new Object [] {}, new String [] {});
        // TODO config admin API

        testJMXSecurityMBean(connection, true, false);
        testKarafConfigAdminMBean(connection, true, false);
    }

    @Test
    public void testJMXSecurityAsAdmin() throws Exception {
        JMXConnector connector = getJMXConnector();
        MBeanServerConnection connection = connector.getMBeanServerConnection();
        ObjectName systemMBean = new ObjectName("org.apache.karaf:type=system,name=root");

        assertEquals(100, connection.getAttribute(systemMBean, "StartLevel"));
        try {
            connection.setAttribute(systemMBean, new Attribute("StartLevel", 101));
            assertEquals(101, connection.getAttribute(systemMBean, "StartLevel"));
        } finally {
            connection.setAttribute(systemMBean, new Attribute("StartLevel", 100));
        }
        assertEquals("Start level should be changed back now",
               100, connection.getAttribute(systemMBean, "StartLevel"));

        ObjectName memoryMBean = new ObjectName("java.lang:type=Memory");
        assertEquals(false, connection.getAttribute(memoryMBean, "Verbose"));
        try {
            connection.setAttribute(memoryMBean, new Attribute("Verbose", true));
            assertEquals(true, connection.getAttribute(memoryMBean, "Verbose"));
        } finally {
            connection.setAttribute(memoryMBean, new Attribute("Verbose", false));
        }
        assertEquals("Verbosity should be changed back to false",
                false, connection.getAttribute(memoryMBean, "Verbose"));
        connection.invoke(memoryMBean, "gc", new Object [] {}, new String [] {});
        // TODO config admin API

        testJMXSecurityMBean(connection, true, true);
    }

    private void testJMXSecurityMBean(MBeanServerConnection connection, boolean isManager, boolean isAdmin)
            throws MalformedObjectNameException, InstanceNotFoundException, MBeanException, ReflectionException, IOException {
        ObjectName securityMBean = new ObjectName("org.apache.karaf:type=security,area=jmx,name=root");

        ObjectName systemMBean = new ObjectName("org.apache.karaf:type=system,name=root");
        assertTrue((Boolean) connection.invoke(securityMBean, "canInvoke",
                new Object [] {systemMBean.toString()},
                new String [] {String.class.getName()}));

        assertTrue((Boolean) connection.invoke(securityMBean, "canInvoke",
                new Object [] {systemMBean.toString(), "getStartLevel"},
                new String [] {String.class.getName(), String.class.getName()}));
        assertEquals(isAdmin, connection.invoke(securityMBean, "canInvoke",
                new Object [] {systemMBean.toString(), "setStartLevel"},
                new String [] {String.class.getName(), String.class.getName()}));
        assertEquals(isAdmin, connection.invoke(securityMBean, "canInvoke",
                new Object [] {systemMBean.toString(), "halt"},
                new String [] {String.class.getName(), String.class.getName()}));

        ObjectName serviceMBean = new ObjectName("org.apache.karaf:type=service,name=root");
        assertTrue((Boolean) connection.invoke(securityMBean, "canInvoke",
                new Object [] {serviceMBean.toString(), "getServices", new String [] {boolean.class.getName()}},
                new String [] {String.class.getName(), String.class.getName(), String[].class.getName()}));
        assertEquals(isManager, connection.invoke(securityMBean, "canInvoke",
                new Object [] {serviceMBean.toString(), "getServices", new String [] {long.class.getName()}},
                new String [] {String.class.getName(), String.class.getName(), String[].class.getName()}));
        assertEquals(isAdmin, connection.invoke(securityMBean, "canInvoke",
                new Object [] {serviceMBean.toString(), "getServices", new String [] {long.class.getName(), boolean.class.getName()}},
                new String [] {String.class.getName(), String.class.getName(), String[].class.getName()}));
        assertEquals(isAdmin, connection.invoke(securityMBean, "canInvoke",
                new Object [] {serviceMBean.toString(), "getServices", new String [] {}},
                new String [] {String.class.getName(), String.class.getName(), String[].class.getName()}));

        Map<String, List<String>> map = new HashMap<String, List<String>>();
        TabularData td = (TabularData) connection.invoke(securityMBean, "canInvoke", new Object [] {map}, new String [] {Map.class.getName()});
        assertEquals(0, td.size());

        Map<String, List<String>> map2 = new HashMap<String, List<String>>();
        map2.put(systemMBean.toString(), Collections.<String>emptyList());
        map2.put(serviceMBean.toString(), Arrays.asList("getServices(boolean)", "getServices(long)", "getServices(long,boolean)", "getServices()"));
        TabularData td2 = (TabularData) connection.invoke(securityMBean, "canInvoke", new Object [] {map2}, new String [] {Map.class.getName()});
        assertEquals(5, td2.size());

        CompositeData cd1 = td2.get(new Object [] {serviceMBean.toString(), "getServices(boolean)"});
        assertEquals(serviceMBean.toString(), cd1.get("ObjectName"));
        assertEquals("getServices(boolean)", cd1.get("Method"));
        assertTrue((Boolean) cd1.get("CanInvoke"));

        CompositeData cd2 = td2.get(new Object [] {serviceMBean.toString(), "getServices(long)"});
        assertEquals(serviceMBean.toString(), cd2.get("ObjectName"));
        assertEquals("getServices(long)", cd2.get("Method"));
        assertEquals(isManager, cd2.get("CanInvoke"));

        CompositeData cd3 = td2.get(new Object [] {serviceMBean.toString(), "getServices(long,boolean)"});
        assertEquals(serviceMBean.toString(), cd3.get("ObjectName"));
        assertEquals("getServices(long,boolean)", cd3.get("Method"));
        assertEquals(isAdmin, cd3.get("CanInvoke"));

        CompositeData cd4 = td2.get(new Object [] {serviceMBean.toString(), "getServices()"});
        assertEquals(serviceMBean.toString(), cd4.get("ObjectName"));
        assertEquals("getServices()", cd4.get("Method"));
        assertEquals(isAdmin, cd4.get("CanInvoke"));

        CompositeData cd5 = td2.get(new Object [] {systemMBean.toString(), ""});
        assertEquals(systemMBean.toString(), cd5.get("ObjectName"));
        assertEquals("", cd5.get("Method"));
        assertTrue((Boolean) cd5.get("CanInvoke"));

        Map<String, List<String>> map3 = new HashMap<String, List<String>>();
        map3.put(serviceMBean.toString(), Collections.singletonList("getServices"));
        TabularData td3 = (TabularData) connection.invoke(securityMBean, "canInvoke", new Object [] {map3}, new String [] {Map.class.getName()});
        assertEquals(1, td3.size());

        CompositeData cd6 = td3.get(new Object [] {serviceMBean.toString(), "getServices"});
        assertEquals(serviceMBean.toString(), cd6.get("ObjectName"));
        assertEquals("getServices", cd6.get("Method"));
        assertTrue((Boolean) cd6.get("CanInvoke"));

        Map<String, List<String>> map4 = new HashMap<String, List<String>>();
        map4.put(systemMBean.toString(), Collections.singletonList("halt"));
        TabularData td4 = (TabularData) connection.invoke(securityMBean, "canInvoke", new Object [] {map4}, new String [] {Map.class.getName()});
        assertEquals(1, td4.size());

        CompositeData cd7 = td4.get(new Object [] {systemMBean.toString(), "halt"});
        assertEquals(systemMBean.toString(), cd7.get("ObjectName"));
        assertEquals("halt", cd7.get("Method"));
        assertEquals(isAdmin, cd7.get("CanInvoke"));
    }

    private void testKarafConfigAdminMBean(MBeanServerConnection connection, boolean isManager, boolean isAdmin)
            throws MalformedObjectNameException, NullPointerException, InstanceNotFoundException, MBeanException, ReflectionException, IOException, AttributeNotFoundException {
        testKarafConfigAdminMBean(connection, "foo.bar", isManager);
        testKarafConfigAdminMBean(connection, "jmx.acl", isAdmin);
        testKarafConfigAdminMBean(connection, "org.apache.karaf.command.acl", isAdmin);
        testKarafConfigAdminMBean(connection, "org.apache.karaf.service.acl", isAdmin);
        testKarafConfigAdminMBean(connection, "org.apache.karaf.somethingelse", isManager);
    }

    private void testKarafConfigAdminMBean(MBeanServerConnection connection, String pidPrefix, boolean shouldSucceed)
            throws MalformedObjectNameException, InstanceNotFoundException, MBeanException, ReflectionException, IOException,
            AttributeNotFoundException {
        String suffix = "." + System.currentTimeMillis() + "_" + counter.incrementAndGet();

        ObjectName mbean = new ObjectName("org.apache.karaf:type=config,name=root");
        String pid1 = pidPrefix + suffix;
        assertJmxInvoke(shouldSucceed, connection, mbean, "create", new Object [] {pid1}, new String [] {String.class.getName()});
        assertJmxInvoke(shouldSucceed, connection, mbean, "setProperty", new Object [] {pid1, "x", "y"}, new String [] {String.class.getName(), String.class.getName(), String.class.getName()});
        Map<?, ?> m1 = (Map<?, ?>) connection.invoke(mbean, "listProperties", new Object [] {pid1}, new String [] {String.class.getName()});
        if (shouldSucceed)
            assertEquals("y", m1.get("x"));
        else
            assertNull(m1.get("x"));
        assertJmxInvoke(shouldSucceed, connection, mbean, "appendProperty", new Object [] {pid1, "x", "z"}, new String [] {String.class.getName(), String.class.getName(), String.class.getName()});
        Map<?, ?> m2 = (Map<?, ?>) connection.invoke(mbean, "listProperties", new Object [] {pid1}, new String [] {String.class.getName()});
        if (shouldSucceed)
            assertEquals("yz", m2.get("x"));
        else
            assertNull(m2.get("x"));

        Map<String, String> newProps = new HashMap<String, String>();
        newProps.put("a.b.c", "abc");
        newProps.put("d.e.f", "def");
        assertJmxInvoke(shouldSucceed, connection, mbean, "update", new Object [] {pid1, newProps}, new String [] {String.class.getName(), Map.class.getName()});
        assertJmxInvoke(shouldSucceed, connection, mbean, "deleteProperty", new Object [] {pid1, "d.e.f"}, new String [] {String.class.getName(), String.class.getName()});
        Map<?, ?> m3 = (Map<?, ?>) connection.invoke(mbean, "listProperties", new Object [] {pid1}, new String [] {String.class.getName()});
        if (shouldSucceed) {
            assertEquals("abc", m3.get("a.b.c"));
            assertNull(m3.get("d.e.f"));
            assertTrue(((List<?>) connection.getAttribute(mbean, "Configs")).contains(pid1));
        } else {
            assertNull(m3.get("a.b.c"));
        }
        assertJmxInvoke(shouldSucceed, connection, mbean, "delete", new Object [] {pid1}, new String [] {String.class.getName()});
        assertFalse(((List<?>) connection.getAttribute(mbean, "Configs")).contains(pid1));
    }

    private Object assertJmxInvoke(boolean expectSuccess, MBeanServerConnection connection, ObjectName mbean, String method,
            Object[] params, String[] signature) throws InstanceNotFoundException, MBeanException, ReflectionException, IOException {
        try {
            Object result = connection.invoke(mbean, method, params, signature);
            assertTrue(expectSuccess);
            return result;
        } catch (SecurityException se) {
            assertFalse(expectSuccess);
            return null;
        }
    }

    private void assertSetAttributeSecEx(MBeanServerConnection connection, ObjectName mbeanObjectName,
            Attribute attribute) throws InstanceNotFoundException, AttributeNotFoundException, InvalidAttributeValueException, MBeanException, ReflectionException, IOException {
        try {
            connection.setAttribute(mbeanObjectName, attribute);
            fail("Expecting a SecurityException");
        } catch (SecurityException se) {
            // good
        }
    }

    private void assertInvokeSecEx(MBeanServerConnection connection, ObjectName mbeanObjectName,
            String method) throws InstanceNotFoundException, MBeanException, ReflectionException, IOException {
        try {
            connection.invoke(mbeanObjectName, method, new Object[] {}, new String [] {});
            fail("Expecting a SecurityException");
        } catch (SecurityException se) {
            // good
        }
    }
}
