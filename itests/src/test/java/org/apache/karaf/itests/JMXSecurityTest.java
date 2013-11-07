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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;

import javax.management.Attribute;
import javax.management.AttributeNotFoundException;
import javax.management.InstanceNotFoundException;
import javax.management.InvalidAttributeValueException;
import javax.management.MBeanException;
import javax.management.MBeanServerConnection;
import javax.management.ObjectName;
import javax.management.ReflectionException;
import javax.management.remote.JMXConnector;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;

@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class JMXSecurityTest extends KarafTestSupport {
    private static AtomicInteger counter = new AtomicInteger(0);

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

        ObjectName securityMBean = new ObjectName("org.apache.karaf:type=security,area=jmx,name=root");
        assertTrue((Boolean) connection.invoke(securityMBean, "canInvoke",
                new Object [] {systemMBean.toString()},
                new String [] {String.class.getName()}));

        assertTrue((Boolean) connection.invoke(securityMBean, "canInvoke",
                new Object [] {systemMBean.toString(), "getStartLevel"},
                new String [] {String.class.getName(), String.class.getName()}));
        assertFalse((Boolean) connection.invoke(securityMBean, "canInvoke",
                new Object [] {systemMBean.toString(), "setStartLevel"},
                new String [] {String.class.getName(), String.class.getName()}));
        assertFalse((Boolean) connection.invoke(securityMBean, "canInvoke",
                new Object [] {systemMBean.toString(), "halt"},
                new String [] {String.class.getName(), String.class.getName()}));

        ObjectName serviceMBean = new ObjectName("org.apache.karaf:type=service,name=root");
        assertTrue((Boolean) connection.invoke(securityMBean, "canInvoke",
                new Object [] {serviceMBean.toString(), "getService", new String [] {boolean.class.getName()}},
                new String [] {String.class.getName(), String.class.getName(), String[].class.getName()}));
        assertFalse((Boolean) connection.invoke(securityMBean, "canInvoke",
                new Object [] {serviceMBean.toString(), "getService", new String [] {long.class.getName()}},
                new String [] {String.class.getName(), String.class.getName(), String[].class.getName()}));
// TODO why does this fail?
//        assertFalse((Boolean) connection.invoke(securityMBean, "canInvoke",
//                new Object [] {serviceMBean.toString(), "getService", new String [] {}},
//                new String [] {String.class.getName(), String.class.getName(), String[].class.getName()}));
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


    /*
    @Test
    public void listCommand() throws Exception {
        String configListOutput = executeCommand("config:list");
        System.out.println(configListOutput);
        assertFalse(configListOutput.isEmpty());
        configListOutput = executeCommand("config:list \"(service.pid=org.apache.karaf.features)\"");
        System.out.println(configListOutput);
        assertFalse(configListOutput.isEmpty());
    }

    @SuppressWarnings("unchecked")
    //@Test
    public void configsViaMBean() throws Exception {
        JMXConnector connector = null;
        try {
            connector = this.getJMXConnector();
            MBeanServerConnection connection = connector.getMBeanServerConnection();
            ObjectName name = new ObjectName("org.apache.karaf:type=config,name=root");
            List<String> configs = (List<String>) connection.getAttribute(name, "Configs");
            assertTrue(configs.size() > 0);
            assertTrue(configs.contains("org.apache.karaf.features"));
            Map<String, String> properties = (Map<String, String>) connection.invoke(name, "listProperties", new Object[]{ "org.apache.karaf.features" }, new String[]{ "java.lang.String" });
            assertTrue(properties.keySet().size() > 0);
        } finally {
            if (connector != null)
                connector.close();
        }
    }
    */
}
