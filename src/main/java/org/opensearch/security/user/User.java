/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.user;

import java.io.IOException;
import java.io.Serializable;
import java.util.*;

import com.google.common.collect.Lists;

import com.jayway.jsonpath.JsonPath;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.security.privileges.UserAttributes;

/**
 * A authenticated user and attributes associated to them (like roles, tenant, custom attributes)
 * <p/>
 * <b>Do not subclass from this class!</b>
 *
 */
public class User implements Serializable, Writeable, CustomAttributesAware {

    public static Builder forUser(String username) {
        return new Builder().name(username);
    }

    public static final User ANONYMOUS = new User(
        "opendistro_security_anonymous",
        Lists.newArrayList("opendistro_security_anonymous_backendrole"),
        null
    );

    // This is a default user that is injected into a transport request when a user info is not present and passive_intertransport_auth is
    // enabled.
    // This is to be used in scenarios where some of the nodes do not have security enabled, and therefore do not pass any user information
    // in threadcontext, yet we need the communication to not break between the nodes.
    // Attach the required permissions to either the user or the backend role.
    public static final User DEFAULT_TRANSPORT_USER = new User(
        "opendistro_security_default_transport_user",
        Lists.newArrayList("opendistro_security_default_transport_backendrole"),
        null
    );

    private String authDomain;

    private static final long serialVersionUID = -5500938501822658596L;
    private final String name;
    /**
     * roles == backend_roles
     */
    private Set<String> roles = Collections.synchronizedSet(new HashSet<String>());
    private Set<String> securityRoles = Collections.synchronizedSet(new HashSet<String>());
    private String requestedTenant;
    private Map<String, String> attributes = Collections.synchronizedMap(new HashMap<>());
    private boolean isInjected = false;

    public User(String name, AuthDomainInfo authDomainInfo, Set<String> roles, Set<String> securityRoles, String requestedTenant, Map<String, String> attributes,
                boolean isInjected) {
        super();
        this.name = name;
        this.authDomain = authDomainInfo != null ? authDomainInfo.toInfoString() : null;
        this.roles = roles;
        this.securityRoles = securityRoles;
        this.requestedTenant = requestedTenant;
        this.attributes = attributes;
        this.isInjected = isInjected;
    }

    public User(final StreamInput in) throws IOException {
        super();
        name = in.readString();
        roles.addAll(in.readList(StreamInput::readString));
        requestedTenant = in.readString();
        if (requestedTenant.isEmpty()) {
            requestedTenant = null;
        }
        attributes = Collections.synchronizedMap(in.readMap(StreamInput::readString, StreamInput::readString));
        securityRoles.addAll(in.readList(StreamInput::readString));
    }

    /**
     * Create a new authenticated user
     *
     * @param name The username (must not be null or empty)
     * @param roles Roles of which the user is a member off (maybe null)
     * @param customAttributes Custom attributes associated with this (maybe null)
     * @throws IllegalArgumentException if name is null or empty
     */
    public User(final String name, final Collection<String> roles, final AuthCredentials customAttributes) {
        super();

        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("name must not be null or empty");
        }

        this.name = name;

        if (roles != null) {
            this.addRoles(roles);
        }

        if (customAttributes != null) {
            this.attributes.putAll(customAttributes.getAttributes());
        }

    }

    /**
     * Create a new authenticated user without roles and attributes
     *
     * @param name The username (must not be null or empty)
     * @throws IllegalArgumentException if name is null or empty
     */
    public User(final String name) {
        this(name, null, null);
    }

    public final String getName() {
        return name;
    }

    public String getAuthDomain() {
        return authDomain;
    }

    /**
     *
     * @return A unmodifiable set of the backend roles this user is a member of
     */
    public final Set<String> getRoles() {
        return Collections.unmodifiableSet(roles);
    }

    /**
     * Associate this user with a backend role
     *
     * @param role The backend role
     */
    public final void addRole(final String role) {
        this.roles.add(role);
    }

    /**
     * Associate this user with a set of backend roles
     *
     * @param roles The backend roles
     */
    public final void addRoles(final Collection<String> roles) {
        if (roles != null) {
            this.roles.addAll(roles);
        }
    }

    /**
     * Check if this user is a member of a backend role
     *
     * @param role The backend role
     * @return true if this user is a member of the backend role, false otherwise
     */
    public final boolean isUserInRole(final String role) {
        return this.roles.contains(role);
    }

    /**
     * Associate this user with a set of custom attributes
     *
     * @param attributes custom attributes
     */
    public final void addAttributes(final Map<String, String> attributes) {
        if (attributes != null) {
            this.attributes.putAll(attributes);
        }
    }

    public final String getRequestedTenant() {
        return requestedTenant;
    }

    public final void setRequestedTenant(String requestedTenant) {
        this.requestedTenant = requestedTenant;
    }

    public boolean isInjected() {
        return isInjected;
    }

    public void setInjected(boolean isInjected) {
        this.isInjected = isInjected;
    }

    public final String toStringWithAttributes() {
        return "User [name="
            + name
            + ", backend_roles="
            + roles
            + ", requestedTenant="
            + requestedTenant
            + ", attributes="
            + attributes
            + "]";
    }

    @Override
    public final String toString() {
        return "User [name=" + name + ", backend_roles=" + roles + ", requestedTenant=" + requestedTenant + "]";
    }

    @Override
    public final int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (name == null ? 0 : name.hashCode());
        return result;
    }

    @Override
    public final boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (!(obj instanceof User)) {
            return false;
        }
        final User other = (User) obj;
        if (name == null) {
            if (other.name != null) {
                return false;
            }
        } else if (!name.equals(other.name)) {
            return false;
        }
        return true;
    }

    /**
     * Copy all backend roles from another user
     *
     * @param user The user from which the backend roles should be copied over
     */
    public final void copyRolesFrom(final User user) {
        if (user != null) {
            this.addRoles(user.getRoles());
        }
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(name);
        out.writeStringCollection(new ArrayList<String>(roles));
        out.writeString(requestedTenant == null ? "" : requestedTenant);
        out.writeMap(attributes, StreamOutput::writeString, StreamOutput::writeString);
        out.writeStringCollection(securityRoles == null ? Collections.emptyList() : new ArrayList<String>(securityRoles));
    }

    /**
     * Get the custom attributes associated with this user
     *
     * @return A modifiable map with all the current custom attributes associated with this user
     */
    public synchronized final Map<String, String> getCustomAttributesMap() {
        if (attributes == null) {
            attributes = Collections.synchronizedMap(new HashMap<>());
        }
        return attributes;
    }

    public final void addSecurityRoles(final Collection<String> securityRoles) {
        if (securityRoles != null && this.securityRoles != null) {
            this.securityRoles.addAll(securityRoles);
        }
    }

    public final Set<String> getSecurityRoles() {
        return this.securityRoles == null
            ? Collections.synchronizedSet(Collections.emptySet())
            : Collections.unmodifiableSet(this.securityRoles);
    }

    /**
     * Check the custom attributes associated with this user
     *
     * @return true if it has a service account attributes. otherwise false
     */
    public boolean isServiceAccount() {
        Map<String, String> userAttributesMap = this.getCustomAttributesMap();
        return userAttributesMap != null && "true".equals(userAttributesMap.get("attr.internal.service"));
    }


    public static class Builder {
        private String name;
        private String subName;
        private AuthDomainInfo authDomainInfo;
        private String type;
        private final Set<String> backendRoles = new HashSet<String>();
        private final Set<String> securityRoles = new HashSet<String>();
        private String requestedTenant;
        private Map<String, String> attributes = new HashMap<>();
        private Map<String, Object> structuredAttributes = new HashMap<>();
        private boolean injected;
        private Object specialAuthzConfig;
        private boolean authzComplete;

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder subName(String subName) {
            this.subName = subName;
            return this;
        }

        public Builder authDomainInfo(AuthDomainInfo authDomainInfo) {
            if (this.authDomainInfo == null) {
                this.authDomainInfo = authDomainInfo;
            } else {
                this.authDomainInfo = this.authDomainInfo.add(authDomainInfo);
            }
            return this;
        }

        public Builder type(String type) {
            this.type = type;
            return this;
        }

        public Builder requestedTenant(String requestedTenant) {
            this.requestedTenant = requestedTenant;
            return this;
        }

//        public Builder with(AuthCredentials authCredentials) {
//            this.authDomainInfo(authCredentials.getAuthDomainInfo());
//            this.backendRoles(authCredentials.getBackendRoles());
//            this.oldAttributes(authCredentials.getAttributes());
//            this.attributes(authCredentials.getStructuredAttributes());
//            return this;
//        }

        public Builder backendRoles(String... backendRoles) {
            return this.backendRoles(Arrays.asList(backendRoles));
        }

        public Builder backendRoles(Collection<String> backendRoles) {
            if (backendRoles != null) {
                this.backendRoles.addAll(backendRoles);
            }
            return this;
        }

        public Builder searchGuardRoles(String... searchGuardRoles) {
            return this.searchGuardRoles(Arrays.asList(searchGuardRoles));
        }

        public Builder searchGuardRoles(Collection<String> securityRoles) {
            if (securityRoles != null) {
                this.securityRoles.addAll(securityRoles);
            }
            return this;
        }

        @Deprecated
        public Builder oldAttributes(Map<String, String> attributes) {
            this.attributes.putAll(attributes);
            return this;
        }

//        public Builder attributes(Map<String, Object> attributes) {
//            UserAttributes.validate(attributes);
//            this.structuredAttributes.putAll(attributes);
//            return this;
//        }
//
//        public Builder attribute(String key, Object value) {
//            UserAttributes.validate(value);
//            this.structuredAttributes.put(key, value);
//            return this;
//        }
//
//        public Builder attributesByJsonPath(Map<String, JsonPath> jsonPathMap, Object source) {
//            UserAttributes.addAttributesByJsonPath(jsonPathMap, source, this.structuredAttributes);
//            return this;
//        }

        @Deprecated
        public Builder oldAttribute(String key, String value) {
            this.attributes.put(key, value);
            return this;
        }

        public Builder injected() {
            this.injected = true;
            return this;
        }

        public Builder specialAuthzConfig(Object specialAuthzConfig) {
            this.specialAuthzConfig = specialAuthzConfig;
            return this;
        }

        public Builder authzComplete() {
            this.authzComplete = true;
            return this;
        }

        public User build() {
            return new User(name, authDomainInfo, backendRoles, securityRoles, requestedTenant,
                     attributes, injected);
        }
    }
}
