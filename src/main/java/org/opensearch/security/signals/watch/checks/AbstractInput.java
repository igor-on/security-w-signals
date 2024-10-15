package org.opensearch.security.signals.watch.checks;

import java.util.Map;

import org.opensearch.security.signals.execution.WatchExecutionContext;
import org.opensearch.security.signals.support.NestedValueMap;
import org.opensearch.security.signals.support.NestedValueMap.Path;
import com.google.common.base.Strings;

public abstract class AbstractInput extends Check {
    protected final String target;

    public AbstractInput(String name, String target) {
        super(name);
        this.target = target;
    }

    protected void setResult(WatchExecutionContext ctx, Object result) {

        NestedValueMap data = ctx.getContextData().getData();

        if (Strings.isNullOrEmpty(target) || "_top".equals(target)) {
            data.clear();

            if (result instanceof Map) {
                data.putAllFromAnyMap((Map<?, ?>) result);
            } else {
                data.put("_value", result);
            }
        } else {
            data.put(Path.parse(target), result);
        }
    }
}
