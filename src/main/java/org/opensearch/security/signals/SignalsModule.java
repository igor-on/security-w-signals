package org.opensearch.security.signals;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
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

import org.opensearch.security.BaseDependencies;
import org.opensearch.security.modules.SearchGuardModule;
import org.opensearch.security.modules.state.ComponentState;
import org.opensearch.security.modules.state.ComponentStateProvider;
import org.opensearch.security.searchsupport.jobs.actions.CheckForExecutingTriggerAction;
import org.opensearch.security.searchsupport.jobs.actions.SchedulerConfigUpdateAction;
import org.opensearch.security.searchsupport.jobs.actions.TransportCheckForExecutingTriggerAction;
import org.opensearch.security.searchsupport.jobs.actions.TransportSchedulerConfigUpdateAction;
import com.floragunn.signals.actions.account.config_update.DestinationConfigUpdateAction;
import com.floragunn.signals.actions.account.config_update.TransportDestinationConfigUpdateAction;
import com.floragunn.signals.actions.account.delete.DeleteAccountAction;
import com.floragunn.signals.actions.account.delete.TransportDeleteAccountAction;
import com.floragunn.signals.actions.account.get.GetAccountAction;
import com.floragunn.signals.actions.account.get.TransportGetAccountAction;
import com.floragunn.signals.actions.account.put.PutAccountAction;
import com.floragunn.signals.actions.account.put.TransportPutAccountAction;
import com.floragunn.signals.actions.account.search.SearchAccountAction;
import com.floragunn.signals.actions.account.search.TransportSearchAccountAction;
import com.floragunn.signals.actions.admin.start_stop.StartStopAction;
import com.floragunn.signals.actions.admin.start_stop.TransportStartStopAction;
import com.floragunn.signals.actions.settings.get.GetSettingsAction;
import com.floragunn.signals.actions.settings.get.TransportGetSettingsAction;
import com.floragunn.signals.actions.settings.put.PutSettingsAction;
import com.floragunn.signals.actions.settings.put.TransportPutSettingsAction;
import com.floragunn.signals.actions.settings.update.SettingsUpdateAction;
import com.floragunn.signals.actions.settings.update.TransportSettingsUpdateAction;
import com.floragunn.signals.actions.tenant.start_stop.StartStopTenantAction;
import com.floragunn.signals.actions.tenant.start_stop.TransportStartStopTenantAction;
import com.floragunn.signals.actions.watch.ack.AckWatchAction;
import com.floragunn.signals.actions.watch.ack.TransportAckWatchAction;
import com.floragunn.signals.actions.watch.activate_deactivate.TransportDeActivateWatchAction;
import com.floragunn.signals.actions.watch.delete.DeleteWatchAction;
import com.floragunn.signals.actions.watch.delete.TransportDeleteWatchAction;
import com.floragunn.signals.actions.watch.execute.ExecuteWatchAction;
import com.floragunn.signals.actions.watch.execute.TransportExecuteWatchAction;
import com.floragunn.signals.actions.watch.get.GetWatchAction;
import com.floragunn.signals.actions.watch.get.TransportGetWatchAction;
import com.floragunn.signals.actions.watch.put.PutWatchAction;
import com.floragunn.signals.actions.watch.put.TransportPutWatchAction;
import com.floragunn.signals.actions.watch.search.SearchWatchAction;
import com.floragunn.signals.actions.watch.search.TransportSearchWatchAction;
import com.floragunn.signals.actions.watch.state.get.GetWatchStateAction;
import com.floragunn.signals.actions.watch.state.get.TransportGetWatchStateAction;
import com.floragunn.signals.actions.watch.state.search.SearchWatchStateAction;
import com.floragunn.signals.actions.watch.state.search.TransportSearchWatchStateAction;
import com.floragunn.signals.api.AccountApiAction;
import com.floragunn.signals.api.AckWatchApiAction;
import com.floragunn.signals.api.ConvertWatchApiAction;
import com.floragunn.signals.api.DeActivateGloballyAction;
import com.floragunn.signals.api.DeActivateTenantAction;
import com.floragunn.signals.api.DeActivateWatchAction;
import com.floragunn.signals.api.ExecuteWatchApiAction;
import com.floragunn.signals.api.SearchAccountApiAction;
import com.floragunn.signals.api.SearchWatchApiAction;
import com.floragunn.signals.api.SearchWatchStateApiAction;
import com.floragunn.signals.api.SettingsApiAction;
import com.floragunn.signals.api.WatchApiAction;
import com.floragunn.signals.api.WatchStateApiAction;
import com.floragunn.signals.script.types.SignalsObjectFunctionScript;
import com.floragunn.signals.settings.SignalsSettings;
import com.floragunn.signals.watch.checks.Calc;
import com.floragunn.signals.watch.checks.Condition;
import com.floragunn.signals.watch.checks.Transform;
import com.floragunn.signals.watch.severity.SeverityMapping;

public class SignalsModule implements SearchGuardModule<Void>, ComponentStateProvider {

    private final boolean enabled;
    private final ComponentState moduleState = new ComponentState(100, null, "signals", SignalsModule.class);

    public SignalsModule(Settings settings) {
        enabled = settings.getAsBoolean("signals.enabled", true);
        
        if (!enabled) {
            moduleState.setState(ComponentState.State.DISABLED);
        }
    }
    
    public SignalsModule() {
        enabled = true;
    }

    @Override
    public List<RestHandler> getRestHandlers(Settings settings, RestController controller, ClusterSettings clusterSettings,
            IndexScopedSettings indexScopedSettings, SettingsFilter settingsFilter, IndexNameExpressionResolver indexNameExpressionResolver,
            ScriptService scriptService, Supplier<DiscoveryNodes> nodesInCluster) {
        if (enabled) {
            return Arrays.asList(new WatchApiAction(settings), new ExecuteWatchApiAction(settings, scriptService),
                    new DeActivateWatchAction(settings, controller), new AckWatchApiAction(settings, controller), new SearchWatchApiAction(),
                    new AccountApiAction(settings, controller), new SearchAccountApiAction(), new WatchStateApiAction(settings, controller),
                    new SettingsApiAction(settings, controller), new DeActivateTenantAction(settings, controller),
                    new DeActivateGloballyAction(settings, controller), new SearchWatchStateApiAction(), new ConvertWatchApiAction(settings));
        } else {
            return Collections.emptyList();
        }
    }

    @Override
    public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        if (enabled) {

            return Arrays.asList(new ActionHandler<>(AckWatchAction.INSTANCE, TransportAckWatchAction.class),
                    new ActionHandler<>(GetWatchAction.INSTANCE, TransportGetWatchAction.class),
                    new ActionHandler<>(PutWatchAction.INSTANCE, TransportPutWatchAction.class),
                    new ActionHandler<>(DeleteWatchAction.INSTANCE, TransportDeleteWatchAction.class),
                    new ActionHandler<>(SearchWatchAction.INSTANCE, TransportSearchWatchAction.class),
                    new ActionHandler<>(com.floragunn.signals.actions.watch.activate_deactivate.DeActivateWatchAction.INSTANCE,
                            TransportDeActivateWatchAction.class),
                    new ActionHandler<>(ExecuteWatchAction.INSTANCE, TransportExecuteWatchAction.class),
                    new ActionHandler<>(DestinationConfigUpdateAction.INSTANCE, TransportDestinationConfigUpdateAction.class),
                    new ActionHandler<>(PutAccountAction.INSTANCE, TransportPutAccountAction.class),
                    new ActionHandler<>(GetAccountAction.INSTANCE, TransportGetAccountAction.class),
                    new ActionHandler<>(DeleteAccountAction.INSTANCE, TransportDeleteAccountAction.class),
                    new ActionHandler<>(SearchAccountAction.INSTANCE, TransportSearchAccountAction.class),
                    new ActionHandler<>(GetWatchStateAction.INSTANCE, TransportGetWatchStateAction.class),
                    new ActionHandler<>(SettingsUpdateAction.INSTANCE, TransportSettingsUpdateAction.class),
                    new ActionHandler<>(GetSettingsAction.INSTANCE, TransportGetSettingsAction.class),
                    new ActionHandler<>(PutSettingsAction.INSTANCE, TransportPutSettingsAction.class),
                    new ActionHandler<>(StartStopTenantAction.INSTANCE, TransportStartStopTenantAction.class),
                    new ActionHandler<>(StartStopAction.INSTANCE, TransportStartStopAction.class),
                    new ActionHandler<>(SearchWatchStateAction.INSTANCE, TransportSearchWatchStateAction.class),
                    new ActionHandler<>(SchedulerConfigUpdateAction.INSTANCE, TransportSchedulerConfigUpdateAction.class),
                    new ActionHandler<>(CheckForExecutingTriggerAction.INSTANCE, TransportCheckForExecutingTriggerAction.class)

            );
        } else {
            return Collections.emptyList();
        }
    }

    @Override
    public List<ScriptContext<?>> getContexts() {
        if (enabled) {
            return Arrays.asList(Condition.ConditionScript.CONTEXT, Transform.TransformScript.CONTEXT, Calc.CalcScript.CONTEXT,
                    SeverityMapping.SeverityValueScript.CONTEXT, SignalsObjectFunctionScript.CONTEXT);
        } else {
            return Collections.emptyList();
        }
    }

    @SuppressWarnings("resource")
    @Override
    public Collection<Object> createComponents(BaseDependencies baseDependencies) {
        if (enabled) {
            return new Signals(baseDependencies.getSettings(), moduleState).createComponents(baseDependencies.getLocalClient(),
                    baseDependencies.getClusterService(), baseDependencies.getThreadPool(), baseDependencies.getResourceWatcherService(),
                    baseDependencies.getScriptService(), baseDependencies.getxContentRegistry(), baseDependencies.getEnvironment(),
                    baseDependencies.getNodeEnvironment(), baseDependencies.getInternalAuthTokenProvider(),
                    baseDependencies.getProtectedConfigIndexService(), baseDependencies.getDynamicConfigFactory(), baseDependencies.getDiagnosticContext());
        } else {
            return Collections.emptyList();
        }
    }

    @Override
    public List<Setting<?>> getSettings() {
        return SignalsSettings.StaticSettings.getAvailableSettings();
    }

    @Override
    public void onNodeStarted() {
    }

    @Override
    public ComponentState getComponentState() {
        return moduleState;
    }

}
