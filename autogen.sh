#!/bin/sh
aclocal
autoconf
libtoolize --force
automake --add-missing --foreign
