package org.opensearch.security.privileges;

import java.util.Set;

import org.opensearch.core.common.transport.TransportAddress;

import org.opensearch.security.securityconf.SecurityRoles;
import org.opensearch.security.user.User;

public interface SpecialPrivilegesEvaluationContext {
    User getUser();

    Set<String> getMappedRoles();

    SecurityRoles getSgRoles();

    default TransportAddress getCaller() {
        return null;
    }

    default boolean requiresPrivilegeEvaluationForLocalRequests() {
        return false;
    }

    default boolean isSgConfigRestApiAllowed() {
        return false;
    }
}
