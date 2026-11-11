"""Stage A -- the image model.

Everything in this package describes the unpacked firmware image *without reference
to any particular source domain*. That separation is deliberate: this is the
expensive work (walking the tree, reading inodes, parsing every config file), and
it is computed once and cached, so analysing a second subject reuses it.
"""
