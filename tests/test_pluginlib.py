# SPDX-FileCopyrightText: © Atakama, Inc <support@atakama.com>
# SPDX-License-Identifier: LGPL-3.0-or-later

# note: do not move these packages around!

from unittest.mock import patch

import pytest

from atakama import (
    DetectorPlugin,
    FileChangedPlugin,
    Plugin,
    PluginVersionMissingError,
    SDK_VERSION_NAME,
)
from atakama.plugin_base import is_abstract, StartupPlugin


def test_simple_detector():
    # we just test that we can write a class to spec
    class ExamplePlugin(DetectorPlugin):
        @staticmethod
        def name():
            return "yo"

        def needs_encryption(self, full_path):
            return True

    assert Plugin.get_by_name("yo") is ExamplePlugin

    ExamplePlugin({"arg": 1})

    assert ExamplePlugin.type() == "DetectorPlugin"

    assert "yo" in Plugin.all_names()


def test_simple_startup_plugin():
    # we just test that we can write a class to spec
    class ExampleStartupPlugin(StartupPlugin):
        @staticmethod
        def name():
            return "simple-startup-plugin"

    assert Plugin.get_by_name("simple-startup-plugin") is ExampleStartupPlugin

    ExampleStartupPlugin({"arg": 1})

    assert ExampleStartupPlugin.type() == "StartupPlugin"

    assert "simple-startup-plugin" in Plugin.all_names()


def test_is_abstract():
    assert is_abstract(DetectorPlugin)


def test_simple_fchange():
    # we just test that we can write a class to spec
    class ExamplePlugin(FileChangedPlugin):
        @staticmethod
        def name():
            return "yo"

        def file_changed(self, full_path):
            return

    assert Plugin.get_by_name("yo") is ExamplePlugin

    ExamplePlugin({"arg": 1})


def test_get_version_from_mod():
    # we just test that we can write a class to spec
    class ExamplePlugin(FileChangedPlugin):
        pass

    with patch.dict(globals(), {SDK_VERSION_NAME: Plugin.CURRENT_SDK_VERSION}):
        assert ExamplePlugin.get_sdk_version() == Plugin.CURRENT_SDK_VERSION


def test_get_version_from_sub():
    from tests.package import InvalidPlugin

    assert InvalidPlugin.get_sdk_version() == Plugin.CURRENT_SDK_VERSION


def test_get_version_failed():
    # we just test that we can write a class to spec
    class ExamplePlugin(FileChangedPlugin):
        pass

    with pytest.raises(PluginVersionMissingError):
        ExamplePlugin.get_sdk_version()
