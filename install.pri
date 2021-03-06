# A custom install path prefix can be provided by passing PREFIX=/absolute/path
# to qmake; if one is not provided, we use the below defaults -
isEmpty(PREFIX) {
    unix:PREFIX = "/usr/local/"
    macx:PREFIX = "/Applications/"
    win32:PREFIX = "../"
}
DATADIR = $$PREFIX/share/
DEFINES += DATADIR=\\\"$$DATADIR\\\" PKGDATADIR=\\\"$$PKGDATADIR\\\"
config.path = $$DATADIR/$${TARGET}

macx {
    target.path = $$PREFIX/Ostinato
} else {
    target.path = $$PREFIX/bin
}

INSTALLS += target config
