package org.opensearch.security.signals.support;

import java.io.IOException;
import java.util.Collections;

import org.opensearch.core.xcontent.ToXContentFragment;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.script.Script;
import org.opensearch.script.ScriptContext;
import org.opensearch.script.ScriptType;

import org.opensearch.security.codova.validation.ConfigValidationException;
import org.opensearch.security.codova.validation.ValidationErrors;
import org.opensearch.security.searchsupport.config.validation.ValueParser;
import org.opensearch.security.signals.watch.init.WatchInitializationService;

public class InlinePainlessScript<Factory> implements ToXContentFragment {
    private final ScriptContext<Factory> scriptContext;
    private final String source;
    private Factory scriptFactory;

    public InlinePainlessScript(ScriptContext<Factory> scriptContext, String source) {
        this.source = source;
        this.scriptContext = scriptContext;
    }

    public void compile(WatchInitializationService watchInitializationService, ValidationErrors validationErrors) {
        this.scriptFactory = watchInitializationService.compile(null, new Script(ScriptType.INLINE, "painless", source, Collections.emptyMap()),
                scriptContext, validationErrors);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {

        builder.value(source);

        return builder;
    }

    public Factory getScriptFactory() {
        return scriptFactory;
    }

    public static class Parser<Factory> implements ValueParser<InlinePainlessScript<Factory>> {
        private final WatchInitializationService watchInitializationService;
        private final ScriptContext<Factory> scriptContext;

        public Parser(ScriptContext<Factory> scriptContext, WatchInitializationService watchInitializationService) {
            this.watchInitializationService = watchInitializationService;
            this.scriptContext = scriptContext;
        }

        @Override
        public InlinePainlessScript<Factory> parse(String string) throws ConfigValidationException {
            ValidationErrors validationErrors = new ValidationErrors();
            InlinePainlessScript<Factory> result = new InlinePainlessScript<Factory>(scriptContext, string);

            result.compile(watchInitializationService, validationErrors);
            validationErrors.throwExceptionForPresentErrors();
            return result;
        }

        @Override
        public String getExpectedValue() {
            return "Painless script";
        }
    }

}
