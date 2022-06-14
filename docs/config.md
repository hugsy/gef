## Configuring GEF

GEF comes with its own configuration and customization system, allowing fine tweaking. The configuration file is located under `~/.gef.rc` by default, and is automatically loaded when GEF is loaded by GDB.
If not configuration file is found, GEF will simply use the default settings.

The configuration file is a Python [`configparser`](https://docs.python.org/3/library/configparser.html). To create a basic file with all settings and their default values, simply run

```bash
gdb -ex 'gef save' -ex quit
```

You can now explore the configuration file under `~/.gef.rc`.
Once in GEF, the configuration settings can be set/unset/modified by the [command `gef config`](/docs/commands/config.md). Without argument the command will simply dump all known settings:

![gef-config](https://i.imgur.com/bd2ZqsU.png)

To update, follow the syntax

```
gef➤  gef config <Module>.<ModuleSetting>  <Value>
```

Any setting updated this way will be specific to the current GDB session. To make permanent, use the following command

```
gef➤  gef save
```

Refer to the [`gef config` command documentation](/docs/commands/config.md) for complete explanation.
