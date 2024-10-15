package org.opensearch.security.signals.watch.checks;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.script.Script;
import org.opensearch.script.ScriptContext;
import org.opensearch.script.ScriptException;
import org.opensearch.script.ScriptType;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.opensearch.security.codova.validation.ConfigValidationException;
import org.opensearch.security.codova.validation.ValidationErrors;
import org.opensearch.security.searchsupport.config.validation.ValidatingJsonNode;
import org.opensearch.security.searchsupport.json.JacksonTools;
import org.opensearch.security.signals.execution.CheckExecutionException;
import org.opensearch.security.signals.execution.WatchExecutionContext;
import org.opensearch.security.signals.script.SignalsScript;
import org.opensearch.security.signals.watch.init.WatchInitializationService;
import com.google.common.base.Strings;

public class Condition extends Check {

    private String source;
    private String lang;
    private Map<String, Object> params;
    private Script script;
    private ConditionScript.Factory scriptFactory;

    public Condition(String name, String source, String lang, Map<String, Object> params) {
        super(name);
        this.source = source;
        this.lang = lang;
        this.params = params != null ? params : Collections.emptyMap();

        script = new Script(ScriptType.INLINE, lang != null ? lang : "painless", source, this.params);
    }

    static Condition create(WatchInitializationService watchInitService, ObjectNode jsonObject) throws ConfigValidationException {
        ValidationErrors validationErrors = new ValidationErrors();
        ValidatingJsonNode vJsonNode = new ValidatingJsonNode(jsonObject, validationErrors);

        vJsonNode.used("type");

        String name = vJsonNode.string("name");
        String source = vJsonNode.string("source");
        String lang = vJsonNode.string("lang");

        Map<String, Object> params = JacksonTools.toMap(vJsonNode.get("params"));

        vJsonNode.validateUnusedAttributes();

        validationErrors.throwExceptionForPresentErrors();

        Condition result = new Condition(name, source, lang, params);

        result.compileScripts(watchInitService);

        return result;
    }

    public void compileScripts(WatchInitializationService watchInitService) throws ConfigValidationException {
        ValidationErrors validationErrors = new ValidationErrors();

        this.scriptFactory = watchInitService.compile("source", script, ConditionScript.CONTEXT, validationErrors);

        validationErrors.throwExceptionForPresentErrors();
    }


    public String getSource() {
        return source;
    }

    public String getLang() {
        return lang;
    }

    public Map<String, Object> getParams() {
        return params;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("type", "condition");

        if (!Strings.isNullOrEmpty(name)) {
            builder.field("name", name);
        }

        if (!Strings.isNullOrEmpty(lang)) {
            builder.field("lang", lang);
        }

        if (!Strings.isNullOrEmpty(source)) {
            builder.field("source", source);
        }

        if (this.params != null && this.params.size() > 0) {
            builder.field("params", this.params);
        }

        builder.endObject();
        return builder;
    }

    @Override
    public boolean execute(WatchExecutionContext ctx) throws CheckExecutionException {
        try {
            ConditionScript conditionScript = scriptFactory.newInstance(script.getParams(), ctx);
            return conditionScript.execute();
        } catch (ScriptException e) {
            throw new CheckExecutionException(this, "Script Execution Error", e);
        }
    }

    public static abstract class ConditionScript extends SignalsScript {

        public static final String[] PARAMETERS = {};

        public ConditionScript(Map<String, Object> params, WatchExecutionContext watchRuntimeContext) {
            super(params, watchRuntimeContext);
        }

        public abstract boolean execute();

        public static interface Factory {
            ConditionScript newInstance(Map<String, Object> params, WatchExecutionContext watcherContext);
        }

        public static ScriptContext<Factory> CONTEXT = new ScriptContext<>("signals_condition", Factory.class);

    }

}
