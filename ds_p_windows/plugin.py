"""Datashark Windows Plugin
"""
from ds_core.api import Artifact, Result, Status
from ds_core.meta import PluginMeta
from ds_core.config import DSConfiguration
from ds_core.plugin import Plugin, generic_plugin_test_app
from ds_core.database import Format
from . import NAME, LOGGER
from .pe import is_portable_executable, process_portable_executable
from .registry import is_registry_hive, process_registry_hive
from .prefetch import is_prefetch, process_prefetch
from .superfetch import is_superfetch, process_superfetch

PROCESSOR_BY_FILE_TYPE_MAP = [
    (is_prefetch, process_prefetch),
    (is_superfetch, process_superfetch),
    (is_registry_hive, process_registry_hive),
    (is_portable_executable, process_portable_executable),
]


class WindowsPlugin(Plugin, metaclass=PluginMeta):
    """Process files extracted from a Windows host"""

    NAME = NAME
    DEPENDS_ON = []
    DESCRIPTION = """
    Refine data from Windows host files
    """
    YARA_RULE_BODY = Plugin.YARA_MATCH_ALL

    def process(self, artifact: Artifact) -> Result:
        """Process a VHD disk image"""
        try:
            for is_func, process_func in PROCESSOR_BY_FILE_TYPE_MAP:
                if is_func(self, artifact):
                    LOGGER.info("%s(%s)", process_func.__name__, artifact)
                    process_func(self, artifact)
            # commit data added by plugin
            self.session.commit()
            # finally set overall processing status to SUCCESS
            status = Status.SUCCESS
        except:
            LOGGER.exception(
                "an exception occured while processing artifact: %s", artifact
            )
            status = Status.FAILURE
        return Result(self, status, artifact)


def instanciate(config: DSConfiguration):
    """Instanciate plugin"""
    return WindowsPlugin(config)


def test():
    """Test plugin"""
    generic_plugin_test_app(instanciate, Format.DATA)
