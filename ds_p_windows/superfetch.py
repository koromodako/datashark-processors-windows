"""Superfetch processing
"""
from ds_core.api import Artifact
from ds_core.plugin import Plugin


def is_superfetch(plugin: Plugin, artifact: Artifact):
    return False


def process_superfetch(plugin: Plugin, artifact: Artifact):
    return
