/*
 * Copyright 2020-2021 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.opensearch.security;

import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

import org.opensearch.security.codova.validation.ConfigVariableProviders;
import org.opensearch.security.auth.BackendRegistry;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.configuration.ProtectedConfigIndexService;
import org.opensearch.security.configuration.secrets.SecretsService;
import org.opensearch.security.internalauthtoken.InternalAuthTokenProvider;
import org.opensearch.security.privileges.SpecialPrivilegesEvaluationContextProviderRegistry;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.StaticSgConfig;
import org.opensearch.security.searchsupport.diag.DiagnosticContext;

public class BaseDependencies {

    private final Settings settings;
    private final Client localClient;
    private final ClusterService clusterService;
    private final ThreadPool threadPool;
    private final ResourceWatcherService resourceWatcherService;
    private final ScriptService scriptService;
    private final NamedXContentRegistry xContentRegistry;
    private final Environment environment;
    private final IndexNameExpressionResolver indexNameExpressionResolver;
    private final DynamicConfigFactory dynamicConfigFactory;
    private final ConfigurationRepository configurationRepository;
    private final ProtectedConfigIndexService protectedConfigIndexService;
    private final SpecialPrivilegesEvaluationContextProviderRegistry specialPrivilegesEvaluationContextProviderRegistry;
    private final NodeEnvironment nodeEnvironment;
    private final InternalAuthTokenProvider internalAuthTokenProvider;
    private final StaticSgConfig staticSgConfig;
    private final DiagnosticContext diagnosticContext;
    private final BackendRegistry backendRegistry;
    private final SecretsService secretsService;
    private final ConfigVariableProviders configVariableProviders;

    public BaseDependencies(Settings settings, Client localClient, ClusterService clusterService, ThreadPool threadPool,
                            ResourceWatcherService resourceWatcherService, ScriptService scriptService, NamedXContentRegistry xContentRegistry,
                            Environment environment, NodeEnvironment nodeEnvironment, IndexNameExpressionResolver indexNameExpressionResolver,
                            DynamicConfigFactory dynamicConfigFactory, StaticSgConfig staticSgConfig, ConfigurationRepository configurationRepository,
                            ProtectedConfigIndexService protectedConfigIndexService, InternalAuthTokenProvider internalAuthTokenProvider,
                            SpecialPrivilegesEvaluationContextProviderRegistry specialPrivilegesEvaluationContextProviderRegistry, BackendRegistry backendRegistry,
                            SecretsService secretsStorageService, ConfigVariableProviders configVariableProviders, DiagnosticContext diagnosticContext) {
        super();
        this.settings = settings;
        this.localClient = localClient;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.resourceWatcherService = resourceWatcherService;
        this.scriptService = scriptService;
        this.xContentRegistry = xContentRegistry;
        this.environment = environment;
        this.nodeEnvironment = nodeEnvironment;
        this.indexNameExpressionResolver = indexNameExpressionResolver;
        this.dynamicConfigFactory = dynamicConfigFactory;
        this.staticSgConfig = staticSgConfig;
        this.configurationRepository = configurationRepository;
        this.protectedConfigIndexService = protectedConfigIndexService;
        this.specialPrivilegesEvaluationContextProviderRegistry = specialPrivilegesEvaluationContextProviderRegistry;
        this.internalAuthTokenProvider = internalAuthTokenProvider;
        this.backendRegistry = backendRegistry;
        this.secretsService = secretsStorageService;
        this.diagnosticContext = diagnosticContext;
        this.configVariableProviders = configVariableProviders;
    }

    public Settings getSettings() {
        return settings;
    }

    public Client getLocalClient() {
        return localClient;
    }

    public ClusterService getClusterService() {
        return clusterService;
    }

    public ThreadPool getThreadPool() {
        return threadPool;
    }

    public ResourceWatcherService getResourceWatcherService() {
        return resourceWatcherService;
    }

    public ScriptService getScriptService() {
        return scriptService;
    }

    public NamedXContentRegistry getxContentRegistry() {
        return xContentRegistry;
    }

    public Environment getEnvironment() {
        return environment;
    }

    public IndexNameExpressionResolver getIndexNameExpressionResolver() {
        return indexNameExpressionResolver;
    }

    public DynamicConfigFactory getDynamicConfigFactory() {
        return dynamicConfigFactory;
    }

    public ConfigurationRepository getConfigurationRepository() {
        return configurationRepository;
    }

    public SpecialPrivilegesEvaluationContextProviderRegistry getSpecialPrivilegesEvaluationContextProviderRegistry() {
        return specialPrivilegesEvaluationContextProviderRegistry;
    }

    public ProtectedConfigIndexService getProtectedConfigIndexService() {
        return protectedConfigIndexService;
    }

    public NodeEnvironment getNodeEnvironment() {
        return nodeEnvironment;
    }

    public InternalAuthTokenProvider getInternalAuthTokenProvider() {
        return internalAuthTokenProvider;
    }

    public StaticSgConfig getStaticSgConfig() {
        return staticSgConfig;
    }

    public DiagnosticContext getDiagnosticContext() {
        return diagnosticContext;
    }

    public BackendRegistry getBackendRegistry() {
        return backendRegistry;
    }

    public SecretsService getSecretsService() {
        return secretsService;
    }

    public ConfigVariableProviders getConfigVariableProviders() {
        return configVariableProviders;
    }


}