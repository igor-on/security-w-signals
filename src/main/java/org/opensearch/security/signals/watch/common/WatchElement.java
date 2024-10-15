package org.opensearch.security.signals.watch.common;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.script.TemplateScript;

import com.fasterxml.jackson.databind.JsonNode;
import org.opensearch.security.signals.execution.WatchExecutionContext;

public abstract class WatchElement implements ToXContentObject {

    public Iterable<? extends WatchElement> getChildren() {
        return Collections.emptyList();
    }

    public <T> T getChildByNameAndType(Class<T> type, String name) {
        if (name == null) {
            return null;
        }

        for (WatchElement o : getChildren()) {
            if (o == null) {
                continue;
            }

            if (type.isAssignableFrom(o.getClass()) && name.equals(o.getName())) {
                return type.cast(o);
            }
        }

        return null;
    }

    public <T> T getChildByNameAndType(Class<T> type, JsonNode jsonNode) {
        if (jsonNode == null) {
            return null;
        }

        return getChildByNameAndType(type, jsonNode.asText());
    }

    public String getName() {
        return null;
    }

    protected String render(WatchExecutionContext ctx, TemplateScript.Factory script) {
        if (script != null) {
            return script.newInstance(ctx.getTemplateScriptParamsAsMap()).execute();
        } else {
            return null;
        }
    }

    protected List<String> render(WatchExecutionContext ctx, List<TemplateScript.Factory> list) {
        if (list == null || list.size() == 0) {
            return Collections.emptyList();
        } else {
            return list.stream().map((script) -> render(ctx, script)).collect(Collectors.toList());
        }
    }
}
