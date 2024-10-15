package org.opensearch.security.signals.confconv.es;

import org.opensearch.security.codova.validation.ValidationErrors;
import org.opensearch.security.codova.validation.errors.ValidationError;
import org.opensearch.security.signals.confconv.ConversionResult;

public class PainlessScriptConverter {
    private final String script;

    PainlessScriptConverter(String script) {
        this.script = script;
    }

    public ConversionResult<String> convertToSignals() {
        if (script == null) {
            return new ConversionResult<String>(null);
        }

        ValidationErrors validationErrors = new ValidationErrors();

        String convertedScript = script;

        if (script.contains("ctx.payload.")) {
            convertedScript = convertedScript.replace("ctx.payload.", "data.");
        }

        if (script.contains("params.")) {
            validationErrors.add(new ValidationError(null, "params script attribute is not supported by Signals"));
        }

        if (script.contains("ctx.metadata.")) {
            convertedScript = convertedScript.replace("ctx.metadata.", "data.");
        }

        if (script.contains("ctx.trigger.")) {
            convertedScript = convertedScript.replace("ctx.trigger.", "trigger.");
        }

        return new ConversionResult<String>(convertedScript);
    }

}
