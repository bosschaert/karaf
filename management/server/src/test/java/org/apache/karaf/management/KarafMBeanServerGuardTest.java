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

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Dictionary;
import java.util.Hashtable;

import javax.management.ObjectName;

import junit.framework.TestCase;

import org.easymock.EasyMock;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;

public class KarafMBeanServerGuardTest extends TestCase {
    public void testRequiredRolesMethodNameOnly() throws Exception {
        Dictionary<String, Object> configuration = new Hashtable<String, Object>();
        configuration.put("doit", "master");
        configuration.put("fryIt", "editor, viewer");
        ConfigurationAdmin ca = getMockConfigAdmin(configuration);

        KarafMBeanServerGuard guard = new KarafMBeanServerGuard();
        guard.setConfigAdmin(ca);

        ObjectName on = ObjectName.getInstance("foo.bar:type=Test");
        assertEquals(Collections.singletonList("master"),
                guard.getRequiredRoles(on, "doit", new Object[] {}, new String [] {}));
        assertEquals(Arrays.asList("editor", "viewer"),
                guard.getRequiredRoles(on, "fryIt", new Object[] {"blah"}, new String [] {"java.lang.String"}));
    }

    public void testRequiredRolesSignature() throws Exception {
        Dictionary<String, Object> configuration = new Hashtable<String, Object>();
        configuration.put("testIt", "master");
        configuration.put("testIt( java.lang.String)", "viewer");
        configuration.put("testIt( java.lang.String ,java.lang.String)", "editor");
        ConfigurationAdmin ca = getMockConfigAdmin(configuration);

        KarafMBeanServerGuard guard = new KarafMBeanServerGuard();
        guard.setConfigAdmin(ca);

        ObjectName on = ObjectName.getInstance("foo.bar:type=Test");
        assertEquals(Collections.singletonList("editor"),
                guard.getRequiredRoles(on, "testIt", new Object[] {"test"}, new String [] {"java.lang.String", "java.lang.String"}));
    }

    private ConfigurationAdmin getMockConfigAdmin(Dictionary<String, Object> configuration) throws IOException,
            InvalidSyntaxException {
        Configuration conf = EasyMock.createMock(Configuration.class);
        EasyMock.expect(conf.getPid()).andReturn("jmx.acl.foo.bar.Test").anyTimes();
        EasyMock.expect(conf.getProperties()).andReturn(configuration).anyTimes();
        EasyMock.replay(conf);

        ConfigurationAdmin ca = EasyMock.createMock(ConfigurationAdmin.class);
        EasyMock.expect(ca.getConfiguration("jmx.acl.foo.bar.Test")).andReturn(conf).anyTimes();
        EasyMock.expect(ca.listConfigurations((String) EasyMock.anyObject())).andReturn(
                new Configuration [] {conf}).anyTimes();
        EasyMock.replay(ca);
        return ca;
    }

    public void xxtestKarafMBeanServerGuard() throws Exception {
        ConfigurationAdmin ca = EasyMock.createMock(ConfigurationAdmin.class);

        KarafMBeanServerGuard guard = new KarafMBeanServerGuard();
        guard.setConfigAdmin(ca);

        ObjectName on = ObjectName.getInstance("foo.bar:type=Test");
        guard.handleInvoke(on, "doit", new Object[] {}, new String [] {});
    }

}
