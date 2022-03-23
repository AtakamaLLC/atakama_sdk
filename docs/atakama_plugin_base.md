# [atakama](atakama.md).plugin_base
Atakama plugin base lib.


[(view source)](https://github.com/AtakamaLLC/atakama_sdk/blob/master/atakama/plugin_base.py)
## DetectorPlugin(Plugin)
#### .needs\_encryption(self, full\_path) -> bool
Return true if the file needs to be encrypted.

This is called any time a file in a secure folder is changed.


#### .watch\_callback(self, full\_path) -> List[str]
Return a list of dependent files to check if they need encryption.

This is called any time a file in a secure folder is changed.



## FileChangedPlugin(Plugin)
#### .file\_changed(self, full\_path) -> None
Called when a file is created or changed within a vault.

Typically used for document (re)classification.



## Plugin(ABC)
Derive from this class to make a new plugin type.


#### .\_\_init\_\_(self, args: Any)
Init instance, passing args defined in the config file.

Only called if config.plugins['name'].enabled is set to True.


#### .name() -> str
Name this plugin.

This is used in the configuration file to enable/disable this plugin.



## StartupPlugin(Plugin)
Plugin for launching things at start and at shutdown.


#### .run\_after\_start(self) -> bool
Runs once at product start, after gui & filesystem are running.

Exceptions prevent startup and may induce a dialog/alert.


#### .run\_before\_start(self) -> bool
Runs once before product start, can be uses to modify the system before startup.

Exceptions cause the system to shut down, and may cause a dialog/alert.


#### .shutdown(self)
Runs at system shutdown, exceptions are logged but ignored.


