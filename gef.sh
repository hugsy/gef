
wget -q -O "$HOME/.gdbinit-gef.py" https://github.com/hugsy/gef/raw/master/gef.py
test -f "$HOME/.gdbinit" && mv "$HOME/.gdbinit" "$HOME/.gdbinit.old"
echo "source $HOME/.gdbinit-gef.py" > "$HOME/.gdbinit"

exit 0
