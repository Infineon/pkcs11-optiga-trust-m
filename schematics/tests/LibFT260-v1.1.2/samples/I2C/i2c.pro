TEMPLATE = app
CONFIG  -= qt
CONFIG  += console

TARGET = i2c

#####################
debug:OBJECTS_DIR   = ./tmp/debug_obj
release:OBJECTS_DIR = ./tmp/release_obj
MOC_DIR     = ./tmp
UI_DIR      = ./tmp

#####################
# LibFT260

INCLUDEPATH  += ../../imports/LibFT260/inc
QMAKE_LIBDIR += ../../imports/LibFT260/lib
debug:LIBS += -lLibFT260

#####################

INCLUDEPATH += ../../common

SOURCES += i2c.cpp
