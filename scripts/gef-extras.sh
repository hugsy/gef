git clone https://github.com/hugsy/gef-extras.git $HOME/gef-extras
gdb -q -ex 'gef config gef.extra_plugins_dir "'$HOME'/gef-extras/scripts"' -ex 'gef config pcustom.struct_path '$HOME'/gef-extras/structs' -ex 'gef save' -ex quit
