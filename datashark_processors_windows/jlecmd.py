"""Datashark Template Plugin
"""
from typing import Dict
from pathlib import Path
from datashark_core.meta import ProcessorMeta
from datashark_core.logging import LOGGING_MANAGER
from datashark_core.processor import ProcessorInterface, ProcessorError
from datashark_core.model.api import Kind, System, ProcessorArgument

NAME = 'windows_jlecmd'
LOGGER = LOGGING_MANAGER.get_logger(NAME)


class JLECmdProcessor(ProcessorInterface, metaclass=ProcessorMeta):
    """Template of a processor"""

    NAME = NAME
    SYSTEM = System.WINDOWS
    ARGUMENTS = []
    DESCRIPTION = """
    Template of a processor, not meant for use, meant for dev
    """

    async def _run(self, arguments: Dict[str, ProcessorArgument]):
        """Process a file using tskape"""
        # retrieve workdir and check access to it
        workdir = self.config.get('datashark.agent.workdir', type=Path)
        if not workdir.is_dir():
            raise ProcessorError("agent-side workdir not found!")
        # TODO: perform processor work here
        raise ProcessorError("not implemented!")
        # commit data added by plugin (if needed)
        #self.session.commit()
