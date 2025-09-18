import importlib
import inspect
import pkgutil

from .DefaultGrammar import DefaultGrammar


def _build_grammar_registry():
    registry = {}
    package_name = __name__
    package_path = __path__

    for _, module_name, _ in pkgutil.walk_packages(package_path, prefix=package_name + '.'):
        try:
            module = importlib.import_module(module_name)

            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (obj.__module__ == module_name and issubclass(obj, DefaultGrammar) and obj is not DefaultGrammar):
                    if name.endswith("Grammar"):
                        proto_name = name[:-len("Grammar")].lower()
                        registry[proto_name] = obj
        except Exception:
            pass
    return registry


_GRAMMAR_REGISTRY = _build_grammar_registry()


def load_grammar(proto: str) -> DefaultGrammar:

    proto = proto.lower()

    GrammarClass = _GRAMMAR_REGISTRY.get(proto, DefaultGrammar)

    return GrammarClass()


__all__ = ['load_grammar', 'DefaultGrammar']




