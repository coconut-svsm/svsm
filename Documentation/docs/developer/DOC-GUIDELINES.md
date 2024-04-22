Documentation Guidelines
========================

This documentation site is generated using [mkdocs](https://www.mkdocs.org/)
from markdown files in the repository at:
[`Documentation/docs`](https://github.com/coconut-svsm/svsm/tree/main/Documentation/docs).

You can add documentation pages to this site by creating a pull request. You
will need to add any new pages to the the [mkdocs configuration
file](https://github.com/coconut-svsm/svsm/tree/main/Documentation/mkdocs.yml)
in the `nav` section. See the mkdocs documentation for more details.

Previewing documentation changes
--------------------------------

The documentation pages can be built locally on a development system in order to
preview the changes before publishing.

The `mkdocs` tool needs to be installed in order to build the site pages. On
openSUSE `mkdocs` can be installed with:

```
$ sudo zypper in python312-mkdocs
```

You can then run a local server that renders the documentation pages with:

```
$ make docsite-serve
```

The documentation can then be previewed at: http://localhost:8000.

Note that the links to the Rustdocs will not work in the preview.

Publishing the documentation
----------------------------

When a PR containing documentation is merged, a github action is used to build
the documentation and push the html files to [the `gh-pages`
branch](https://github.com/coconut-svsm/svsm/tree/gh-pages).

Another github action automatically publishes this branch at the Github pages
site: [https://coconut-svsm.github.io/svsm/](https://coconut-svsm.github.io/svsm/).