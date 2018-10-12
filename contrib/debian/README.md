
Debian
====================
This directory contains files used to package stashd/stash-qt
for Debian-based Linux systems. If you compile stashd/stash-qt yourself, there are some useful files here.

## stash: URI support ##


stash-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install stash-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your stash-qt binary to `/usr/bin`
and the `../../share/pixmaps/stash128.png` to `/usr/share/pixmaps`

stash-qt.protocol (KDE)

