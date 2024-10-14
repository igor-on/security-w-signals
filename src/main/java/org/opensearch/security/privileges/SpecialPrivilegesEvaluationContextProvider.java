package org.opensearch.security.privileges;

import java.util.function.Consumer;

import org.opensearch.common.util.concurrent.ThreadContext;

import org.opensearch.security.user.User;

@FunctionalInterface
public interface SpecialPrivilegesEvaluationContextProvider {
    void provide(User user, ThreadContext threadContext, Consumer<SpecialPrivilegesEvaluationContext> onResult, Consumer<Exception> onFailure);
}
