#
# Generated Makefile - do not edit!
#
# Edit the Makefile in the project folder instead (../Makefile). Each target
# has a -pre and a -post target defined where you can add customized code.
#
# This makefile implements configuration specific macros and targets.


# Environment
MKDIR=mkdir
CP=cp
GREP=grep
NM=nm
CCADMIN=CCadmin
RANLIB=ranlib
CC=gcc
CCC=g++
CXX=g++
FC=gfortran
AS=as

# Macros
CND_PLATFORM=GNU-Linux
CND_DLIB_EXT=so
CND_CONF=Debug
CND_DISTDIR=dist
CND_BUILDDIR=build

# Include project Makefile
include Makefile

# Object Directory
OBJECTDIR=${CND_BUILDDIR}/${CND_CONF}/${CND_PLATFORM}

# Object Files
OBJECTFILES= \
	${OBJECTDIR}/_ext/a2b43386/objecttemplates.o \
	${OBJECTDIR}/main.o


# C Compiler Flags
CFLAGS=-DTPM_POSIX

# CC Compiler Flags
CCFLAGS=-DTPM_POSIX
CXXFLAGS=-DTPM_POSIX

# Fortran Compiler Flags
FFLAGS=

# Assembler Flags
ASFLAGS=

# Link Libraries and Options
LDLIBSOPTIONS=-libmtss -libmtssutils -libmtssutils12

# Build Targets
.build-conf: ${BUILD_SUBPROJECTS}
	"${MAKE}"  -f nbproject/Makefile-${CND_CONF}.mk ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/vesipres_gateway

${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/vesipres_gateway: ${OBJECTFILES}
	${MKDIR} -p ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}
	${LINK.cc} -o ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/vesipres_gateway ${OBJECTFILES} ${LDLIBSOPTIONS} -I/opt/ssl/include/ -L/opt/ssl/lib/ -lcrypto -L/home/vt/Downloads/ibmtss1.3.0

${OBJECTDIR}/_ext/a2b43386/objecttemplates.o: /home/vt/Downloads/ibmtss1.3.0/utils/objecttemplates.c
	${MKDIR} -p ${OBJECTDIR}/_ext/a2b43386
	${RM} "$@.d"
	$(COMPILE.c) -g -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/_ext/a2b43386/objecttemplates.o /home/vt/Downloads/ibmtss1.3.0/utils/objecttemplates.c

${OBJECTDIR}/main.o: main.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/home/vt/Downloads/ibmtss1.3.0/utils -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/main.o main.cpp

# Subprojects
.build-subprojects:

# Clean Targets
.clean-conf: ${CLEAN_SUBPROJECTS}
	${RM} -r ${CND_BUILDDIR}/${CND_CONF}

# Subprojects
.clean-subprojects:

# Enable dependency checking
.dep.inc: .depcheck-impl

include .dep.inc
