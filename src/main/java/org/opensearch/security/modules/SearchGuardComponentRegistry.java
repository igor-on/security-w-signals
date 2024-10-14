package org.opensearch.security.modules;

import java.nio.file.Path;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.opensearch.common.settings.Settings;

import org.opensearch.security.support.ReflectionHelper;

public class SearchGuardComponentRegistry<ComponentType> {

    private Class<ComponentType> componentType;
    private Map<String, ComponentType> instanceMap = new HashMap<>();
    private Map<String, ComponentFactory<? extends ComponentType>> factoryMap = new HashMap<>();
    private Map<String, Class<? extends ComponentType>> classMap = new HashMap<>();
    private Map<String, String> classNameMap = new HashMap<>();

    private Function<ComponentType, String> nameFunction;

    public SearchGuardComponentRegistry(Class<ComponentType> componentType) {
        this.componentType = componentType;
        this.nameFunction = (c) -> c.toString();
    }

    public SearchGuardComponentRegistry(Class<ComponentType> componentType, Function<ComponentType, String> nameFunction) {
        this.componentType = componentType;
        this.nameFunction = nameFunction;
    }

    public void addComponentsWithMatchingType(Collection<?> components) {
        for (Object component : components) {
            if (componentType.isAssignableFrom(component.getClass())) {
                ComponentType typedComponent = componentType.cast(component);
                String name = nameFunction.apply(typedComponent);

                if (name != null) {
                    ensureNameIsVacant(name);
                    this.instanceMap.put(name, typedComponent);
                }
            }
        }
    }

    public SearchGuardComponentRegistry<ComponentType> add(SearchGuardComponentRegistry<ComponentType> registry) {
        this.instanceMap.putAll(registry.instanceMap);
        this.classMap.putAll(registry.classMap);
        this.classNameMap.putAll(registry.classNameMap);
        this.factoryMap.putAll(registry.factoryMap);
        return this;
    }

    public SearchGuardComponentRegistry<ComponentType> seal() {
        this.instanceMap = Collections.unmodifiableMap(this.instanceMap);
        this.classMap = Collections.unmodifiableMap(this.classMap);
        this.classNameMap = Collections.unmodifiableMap(this.classNameMap);
        this.factoryMap = Collections.unmodifiableMap(this.factoryMap);

        return this;
    }

    public SearchGuardComponentRegistry<ComponentType> add(String name, ComponentFactory<? extends ComponentType> instance) {
        ensureNameIsVacant(name);
        this.factoryMap.put(name, instance);
        return this;
    }

    public SearchGuardComponentRegistry<ComponentType> add(List<String> names, ComponentFactory<? extends ComponentType> instance) {
        for (String name : names) {
            ensureNameIsVacant(name);
        }
        for (String name : names) {
            this.factoryMap.put(name, instance);
        }
        return this;
    }

    public SearchGuardComponentRegistry<ComponentType> add(String name, Class<? extends ComponentType> clazz) {
        ensureNameIsVacant(name);
        this.classMap.put(name, clazz);
        return this;
    }

    public SearchGuardComponentRegistry<ComponentType> add(String name, String className) {
        ensureNameIsVacant(name);
        this.classNameMap.put(name, className);
        return this;
    }

    public boolean has(String name) {
        return this.instanceMap.containsKey(name) || this.factoryMap.containsKey(name) || this.classMap.containsKey(name)
                || this.classNameMap.containsKey(name);
    }

    public Object getAny(String name) {
        if (this.instanceMap.containsKey(name)) {
            return this.instanceMap.get(name);
        }

        if (this.factoryMap.containsKey(name)) {
            return this.factoryMap.get(name);
        }

        if (this.classMap.containsKey(name)) {
            return this.classMap.get(name);
        }

        if (this.classNameMap.containsKey(name)) {
            return this.classNameMap.get(name);
        }

        return null;
    }

    public ComponentType getInstance(String clazzOrShortcut, Settings settings, Path configPath) {
        if (this.instanceMap.containsKey(clazzOrShortcut)) {
            ComponentType result = this.instanceMap.get(clazzOrShortcut);
            ReflectionHelper.addLoadedModule(result.getClass());
            return result;
        } else if (this.factoryMap.containsKey(clazzOrShortcut)) {
            ComponentType result = this.factoryMap.get(clazzOrShortcut).create(settings, configPath);
            ReflectionHelper.addLoadedModule(result.getClass());
            return result;
        } else if (this.classMap.containsKey(clazzOrShortcut)) {
            String className = this.classMap.get(clazzOrShortcut).getName();
            return ReflectionHelper.instantiateAAA(className, settings, configPath);
        } else if (this.classNameMap.containsKey(clazzOrShortcut)) {
            String className = this.classNameMap.get(clazzOrShortcut);
            return ReflectionHelper.instantiateAAA(className, settings, configPath);
        } else {
            return ReflectionHelper.instantiateAAA(clazzOrShortcut, settings, configPath);
        }
    }

    public String getClassName(String clazzOrShortcut) {
        if (this.instanceMap.containsKey(clazzOrShortcut)) {
            return this.instanceMap.get(clazzOrShortcut).getClass().getName();
        } else if (this.factoryMap.containsKey(clazzOrShortcut)) {
            return this.factoryMap.get(clazzOrShortcut).getClassName();
        } else if (this.classMap.containsKey(clazzOrShortcut)) {
            return this.classMap.get(clazzOrShortcut).getName();
        } else if (this.classNameMap.containsKey(clazzOrShortcut)) {
            return this.classNameMap.get(clazzOrShortcut);
        } else {
            return clazzOrShortcut;
        }
    }

    private void ensureNameIsVacant(String name) {
        if (this.has(name)) {
            throw new IllegalStateException("A component with name " + name + " is already defined: " + this.getAny(name));
        }
    }

    public interface ComponentFactory<ComponentType> {
        ComponentType create(Settings settings, Path configPath);

        String getClassName();
    }
}
