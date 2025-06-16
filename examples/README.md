# Installing dependencies

On macOS:

1. A working python3 distro with pycose and its dependencies installed

```
pip install pycose
```

If you don't mind running the homebrew python (not recommended for serious python devs) you can usually get away with:

- `brew install python3 virtualenv`
- Put `/opt/homebrew/opt/python3/libexec/bin` before the system python in your PATH.
- `python3 -m venv ~/venvs/pycose && source ~/venvs/pycose/bin/activate`
- `pip install pycose`

2. GNU sed

```
brew install gnu-sed
```

3. cddl-rs CLI package (Rust)

```
cargo install cddl
```

And either add `alias cddl-rs="/Users/rohan/.cargo/bin/cddl"` or change the name in the Makefile from cddl-rs to cddl.

If you don't have rust installed, try `brew install rustup && rustup`

4. cbor-diag package (ruby)

```
gem install cbor-diag 
```

If you don't mind running the homebrew Ruby:

- `brew install ruby`
- Add `/opt/homebrew/opt/ruby/bin` and `/opt/homebrew/opt/ruby/lib/ruby/gems/bin` before the system ruby in your PATH.
- Add `export GEM_HOME=/opt/homebrew/opt/ruby/lib/ruby/gems` to your shell startup

5. node-cbor CLI tools (Node.js)

in the examples directory

```
npm install cbor2 cbor-edn
```

If you don't have node installed, try:

```
brew install pnpm npm
```
