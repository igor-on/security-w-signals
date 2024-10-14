package org.opensearch.security.modules;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;

import org.opensearch.action.ActionRequest;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.IndexScopedSettings;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsFilter;
import org.opensearch.plugins.ActionPlugin.ActionHandler;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.script.ScriptContext;
import org.opensearch.script.ScriptService;

import com.fasterxml.jackson.core.JsonPointer;
import org.opensearch.security.BaseDependencies;
import org.opensearch.security.searchsupport.config.validation.JsonNodeParser;

public interface SearchGuardModule<T> {
    default List<RestHandler> getRestHandlers(Settings settings, RestController restController, ClusterSettings clusterSettings,
            IndexScopedSettings indexScopedSettings, SettingsFilter settingsFilter, IndexNameExpressionResolver indexNameExpressionResolver,
            ScriptService scriptService, Supplier<DiscoveryNodes> nodesInCluster) {
        return Collections.emptyList();
    }

    default List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        return Collections.emptyList();
    }

    default List<ScriptContext<?>> getContexts() {
        return Collections.emptyList();
    }

    default Collection<Object> createComponents(BaseDependencies baseDependencies) {
        return Collections.emptyList();
    }

    default List<Setting<?>> getSettings() {
        return Collections.emptyList();
    }

    default SgConfigMetadata<T> getSgConfigMetadata() {
        return null;
    }
    
    default void onNodeStarted() {
        
    }

    public class SgConfigMetadata<T> {
        private final Class<?> sgConfigType;
        private final String entry;
        private final JsonPointer jsonPointer;
        private final JsonNodeParser<T> configParser;
        private final Consumer<T> configConsumer;

        public SgConfigMetadata(Class<?> sgConfigType, String entry, JsonPointer jsonPointer, JsonNodeParser<T> configParser,
                Consumer<T> configConsumer) {
            super();
            this.sgConfigType = sgConfigType;
            this.entry = entry;
            this.jsonPointer = jsonPointer;
            this.configParser = configParser;
            this.configConsumer = configConsumer;
        }

        public Class<?> getSgConfigType() {
            return sgConfigType;
        }

        public String getEntry() {
            return entry;
        }

        public JsonPointer getJsonPointer() {
            return jsonPointer;
        }

        public JsonNodeParser<T> getConfigParser() {
            return configParser;
        }

        public Consumer<T> getConfigConsumer() {
            return configConsumer;
        }

    }
}
