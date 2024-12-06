AC_INIT([xpolkit],[0.1], [cjacker@foxmail.com])

AM_INIT_AUTOMAKE([foreign dist-xz no-dist-gzip tar-pax])

AC_CONFIG_MACRO_DIRS([m4])

AC_CONFIG_SRCDIR([src])

AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# ***************************
# Check for required packages
# ***************************
PKG_CHECK_MODULES([GLIB], [glib-2.0])
PKG_CHECK_MODULES([POLKIT_AGENT], [polkit-agent-1])
PKG_CHECK_MODULES([GTK], [gtk4])

AC_OUTPUT([
Makefile
src/Makefile
data/Makefile
])
