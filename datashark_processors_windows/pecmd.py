"""Datashark Template Plugin
"""
from typing import List, Tuple, Optional
from pathlib import Path
from datashark_core.meta import ProcessorMeta
from datashark_core.logging import LOGGING_MANAGER
from datashark_core.processor import ProcessorInterface
from datashark_core.model.api import System, ProcessorArgument

NAME = 'windows_pecmd'
LOGGER = LOGGING_MANAGER.get_logger(NAME)


class PECmdProcessor(ProcessorInterface, metaclass=ProcessorMeta):
    """Template of a processor"""

    NAME = NAME
    SYSTEM = System.WINDOWS
    ARGUMENTS = []
    DESCRIPTION = """
    Template of a processor, not meant for use, meant for dev
    """

    async def _run(
        self, filepath: Path, arguments: List[ProcessorArgument]
    ) -> Tuple[bool, Optional[str]]:
        """Process a file using tskape"""
        status = False
        details = None
        try:
            # TODO: perform artifact processing here
            raise NotImplementedError()
            # commit data added by plugin (if needed)
            # self.session.commit()
            # finally set overall processing status to SUCCESS
            status = True
        except:
            LOGGER.exception(
                "an exception occured while processing filepath: %s", filepath
            )
        return status, details
