## Contributing to GEF

## License

`gef` is placed under [MIT license](https://github.com/hugsy/gef/blob/main/LICENSE) which provides
Open-Source access to the code and its use.

By contributing to `gef` code through the _Pull Requests_ mechanism, you accept to release the code
written by you under the said license.

## Submitting a Patch

1.  Fork `gef` repository (requires GitHub account). Sending a patch from the
   `patch` or `git diff --patch` commands is not accepted.
1.  All the packages required for testing and documenting are listed in `tests/requirements.txt`
1.  Adjust your development environment to GEF's: this is achieved using
   [`pre-commit`](https://pre-commit.com/), and getting setup is simply done by
1.  Installing `pre-commit` PIP package (part of the `requirements.txt` file)
1.  Setup `pre-commit` : `pre-commit install`
1.  Write the changes in your local repo making sure to respect the coding style (same indentation
  format, explicit names as possible), comment your code sufficiently so it becomes maintainable by
  someone other than you. Finally if you add a new feature/GDB command, also write the adequate
  documentation (in [`docs/`](docs/))
1.  Submit a pull request
1.  The contributors will review your patch. If it is approved, the change will
   be merged via the GitHub, and you will be seen as contributors. If it needs
   additional work, the repo owner will respond with useful comments.
