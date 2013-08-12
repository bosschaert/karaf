/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.karaf.jaas.command;

import org.apache.karaf.jaas.modules.BackingEngine;
import org.apache.karaf.shell.commands.Argument;
import org.apache.karaf.shell.commands.Command;

@Command(scope = "jaas", name = "group-role-del", description = "Remove a role from a group")
public class GroupRoleDeleteCommand extends JaasCommandSupport {
    @Argument(index = 0, name = "groupname", description = "Group Name", required = true, multiValued = false)
    private String groupname;

    @Argument(index = 1, name = "role", description = "Role", required = true, multiValued = false)
    private String role;

    @Override
    protected Object doExecute(BackingEngine engine) throws Exception {
        engine.deleteGroupRole(groupname, role);
        return null;
    }

    public String getGroupname() {
        return groupname;
    }

    public void setGroupname(String groupname) {
        this.groupname = groupname;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    @Override
    public String toString() {
        return "GroupRoleDeleteCommand {groupname='" + groupname + "', role='" + role + "'}";
    }
}
