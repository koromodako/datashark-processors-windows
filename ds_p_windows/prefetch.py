"""Prefetch processor
"""
from ds_core.api import Artifact
from ds_core.plugin import Plugin


def is_prefetch(plugin: Plugin, artifact: Artifact):
    return False


def process_prefetch(plugin: Plugin, artifact: Artifact):
    return
