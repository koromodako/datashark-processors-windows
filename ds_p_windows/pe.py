"""Portable executable processing
"""
from ds_core.api import Artifact
from ds_core.plugin import Plugin


def is_portable_executable(plugin: Plugin, artifact: Artifact):
    return False


def process_portable_executable(plugin: Plugin, artifact: Artifact):
    return
