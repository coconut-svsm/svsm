#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Copyright (C) 2023 IBM
#
# Author: Claudio Carvalho <cclaudio@linux.ibm.com>
set -e

CURDIR=$(dirname "$(realpath "$0")")
WORKDIR=$(realpath "${CURDIR}/../..")
DOCKER_FILE="${WORKDIR}/scripts/container/opensuse-rust.docker"

IMAGE_NAME=opensuse-rust
CONTAINER_NAME=coconut-build

DOCKER_CMD=$(command -v podman || command -v docker) || {
                echo >&2 "ERR: docker (or podman) not found";
                exit 1
            }

EXTRA_DOCKER_OPTS=""
MOUNT_OPTS=""

if [[ "${DOCKER_CMD}" = *podman ]]; then
    EXTRA_DOCKER_OPTS=" --userns keep-id "
    MOUNT_OPTS=",relabel=shared,rw=true"
fi

# Command line arguments
ARG_REUSE=0

####
#### Help function
####
Help()
{
    echo "Build the SVSM within a container."
    echo
    echo "Syntax: $0 [-r|v|h]"
    echo "options:"
    echo "r    Reuse the ${CONTAINER_NAME} to build the SVSM"
    echo "v    Verbose mode"
    echo "h    Print this help"
}

####
#### ParseOptions function
####
ParseOptions()
{
    while getopts "rvh" option; do
        case $option in
            r) # Reuse option
                ARG_REUSE=1
                ;;
            v) # Verbose mode
                set -x
                ;;
            h) # Display help
                Help
                exit 0
                ;;
            \?) # Invalid option
                echo -e "ERR: Invalid option\n"
                Help
                exit 1
                ;;
        esac
    done
}

####
#### Reuse container to build the SVSM
####
BuildSvsmReuse()
{
    CONTAINER_ID=$("${DOCKER_CMD}" ps -q -f name=${CONTAINER_NAME})

    # Create and start the the container if it's not running
    if [ -z ${CONTAINER_ID} ] ; then

        CONTAINER_ID=$("${DOCKER_CMD}" ps -q -a -f name=${CONTAINER_NAME})

        if [ -z ${CONTAINER_ID} ] ; then
            "${DOCKER_CMD}" create \
                -it --name=${CONTAINER_NAME} \
                --workdir="${WORKDIR}" \
                --user ${USER} \
                --mount type=bind,source="${WORKDIR}",target="${WORKDIR}"${MOUNT_OPTS} \
                $EXTRA_DOCKER_OPTS \
                ${IMAGE_NAME} \
                /bin/bash
        fi

        "${DOCKER_CMD}" start ${CONTAINER_NAME}
    fi

    "${DOCKER_CMD}" exec \
        -it ${CONTAINER_NAME} \
        /bin/bash -c "make clean && make"
}

####
#### Build the SVSM in the container, but delete the container afterwards
####
BuildSvsmDelete()
{
      "${DOCKER_CMD}" run \
          --rm -it \
          --workdir="${WORKDIR}" \
          --user ${USER} \
          --mount type=bind,source="${WORKDIR}",target="${WORKDIR}"${MOUNT_OPTS} \
          $EXTRA_DOCKER_OPTS \
          ${IMAGE_NAME} \
          /bin/bash -c "make clean && make"
}

####
#### Build the docker image
####
BuildDockerImage()
{
    IMAGE_ID=$("${DOCKER_CMD}" images -q ${IMAGE_NAME})

    # Build the container image if it's the first time
    if [ -z ${IMAGE_ID} ] ; then
        "${DOCKER_CMD}" build \
            -t ${IMAGE_NAME} \
            --build-arg USER_NAME=${USER} \
            --build-arg USER_ID=$(id -u) \
            -f "${DOCKER_FILE}" \
            .
    fi
}

####
#### Main block
####

ParseOptions $@

BuildDockerImage

if [ $ARG_REUSE -eq 1 ] ; then
    BuildSvsmReuse
else
    BuildSvsmDelete
fi
