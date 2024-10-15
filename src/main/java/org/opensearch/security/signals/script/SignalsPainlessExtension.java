//package org.opensearch.security.signals.script;
//
//import java.util.Collections;
//import java.util.HashMap;
//import java.util.List;
//import java.util.Map;
//
//import org.apache.logging.log4j.LogManager;
//import org.apache.logging.log4j.Logger;
//import org.opensearch.painless.spi.PainlessExtension;
//import org.opensearch.painless.spi.Whitelist;
//import org.opensearch.painless.spi.WhitelistLoader;
//import org.opensearch.script.ScriptContext;
//
//import org.opensearch.security.signals.SignalsModule;
//
//public class SignalsPainlessExtension implements PainlessExtension {
//    private final static Logger log = LogManager.getLogger(SignalsPainlessExtension.class);
//    private final static SignalsModule MODULE = new SignalsModule();
//
//    @Override
//    public Map<ScriptContext<?>, List<Whitelist>> getContextWhitelists() {
//
//        Whitelist whitelist = WhitelistLoader.loadFromResourceFiles(SignalsPainlessExtension.class, "SignalsPainlessClassWhitelist.txt");
//
//        log.info("Loaded script whitelist: " + whitelist);
//
//        HashMap<ScriptContext<?>, List<Whitelist>> result = new HashMap<>();
//
//        for (ScriptContext<?> context : MODULE.getContexts()) {
//            result.put(context, Collections.singletonList(whitelist));
//        }
//
//        return result;
//    }
//
//}
