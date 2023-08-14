## Debugging

Debugging GEF has a trick, let's see some examples

## Debugging a command execution with pdb

Open gef.py

Search for **class NopCommand(GenericCommand)**, go to do_invoke method and insert:

```python
import pdb; pdb.set_trace()
```

Open a gdb session -> start -> nop

Done!
```bash
gef➤  nop
> /home/dreg/.gef-7c170cf6be3d84b2672a22e43b9128a23fe53c3b.py(6075)do_invoke()
-> args : argparse.Namespace = kwargs["arguments"]
(Pdb) ll
6070 	    @only_if_gdb_running
6071 	    @parse_arguments({"address": "$pc"}, {"--i": 1, "--b": True, "--f": True, "--n": True})
6072 	    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
6073 	        import pdb; pdb.set_trace()
6074
6075 ->	        args : argparse.Namespace = kwargs["arguments"]
6076 	        address = parse_address(args.address)
```

Learn more about [pdb](https://docs.python.org/3/library/pdb.html)

## Debugging a command execution with pycharm

Install [pycharm](https://www.jetbrains.com/help/pycharm/installation-guide.html)

Create a new project:

![pycharm1](https://github.com/hugsy/gef/assets/9882181/600a9522-208a-4f2e-89b2-707136ba020a)

![pycharm2](https://github.com/hugsy/gef/assets/9882181/4cf51b17-6aa0-463f-b538-200dd9e9b5e6)

Go to menu -> Run -> Edit configurations...:

![pycharm3](https://github.com/hugsy/gef/assets/9882181/6fdacda8-c4cc-44e0-8fc1-3b18cf118fbe)

Create a Python Debug Server:

![pycharm4](https://github.com/hugsy/gef/assets/9882181/09f99b28-5716-48be-8a0c-8ed69920c4a0)

![pycharm5](https://github.com/hugsy/gef/assets/9882181/814fe019-c390-4ca3-8605-e3842be04df1)

Debug your new Unnamed:

![pycharm6](https://github.com/hugsy/gef/assets/9882181/f0f1eee9-fcaa-4919-8985-8d7d09907ebd)

![pycharm7](https://github.com/hugsy/gef/assets/9882181/039e8749-b949-49e8-917f-b592f9cf6dac)

Copy the info from output Window to gef.py:

![pycharm8](https://github.com/hugsy/gef/assets/9882181/be24ee23-3101-4b71-b62f-70883c9135ad)

First, add to gef.py:

```python
import pydevd_pycharm
```

Second, search for **class NopCommand(GenericCommand)**, go to do_invoke method and insert:

```python
pydevd_pycharm.settrace('localhost', port=35747, stdoutToServer=True, stderrToServer=True)
```

Open a gdb session -> start -> nop

Done!

![pycharm9](https://github.com/hugsy/gef/assets/9882181/b22ec431-57e7-442a-835e-5817bdac7687)
