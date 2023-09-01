#!/bin/bash

CURDIR=$(dirname $(realpath "$0"))
WORKDIR=$(realpath ${CURDIR}/../..)
DOCKER_FILE=$WORKDIR/scripts/docker/opensuse-rust.docker

IMAGE_NAME=opensuse-rust
CONTAINER_NAME=coconut-build

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
                exit
                ;;
            \?) # Invalid option
                echo -e "ERR: Invalid option\n"
                Help
                exit
                ;;
        esac
    done
}

####
#### Reuse container to build the SVSM
####
BuildSvsmReuse()
{
    CONTAINER_ID=$(docker ps -q -f name=${CONTAINER_NAME})

    # Create and start the the container if it's not running
    if [ -z ${CONTAINER_ID} ] ; then

        CONTAINER_ID=$(docker ps -q -a -f name=${CONTAINER_NAME})

        if [ -z ${CONTAINER_ID} ] ; then
            docker create \
                -it --name=${CONTAINER_NAME} \
                --workdir=${WORKDIR} \
                --user ${USER} \
                --mount type=bind,source=${WORKDIR},target=${WORKDIR} \
                ${IMAGE_NAME} \
                /bin/bash
        fi

        docker start ${CONTAINER_NAME}
    fi

    docker exec \
        -it ${CONTAINER_NAME} \
        /bin/bash -c "source $HOME/.cargo/env && make clean && make"
}

####
#### Build the SVSM in the container, but delete the container afterwards
####
BuildSvsmDelete()
{
    docker run \
        --rm -it \
        --workdir=${WORKDIR} \
        --user ${USER} \
        --mount type=bind,source=${WORKDIR},target=${WORKDIR} \
        ${IMAGE_NAME} \
        /bin/bash -c "source $HOME/.cargo/env && make clean && make"
}

####
#### Build the docker image
####
BuildDockerImage()
{
    IMAGE_ID=$(docker images -q ${IMAGE_NAME})

    # Build the container image if it's the first time
    if [ -z ${IMAGE_ID} ] ; then
        docker build -t ${IMAGE_NAME} --build-arg USER_NAME=${USER} --build-arg USER_ID=$(id -u) -f ${DOCKER_FILE} .
    fi
}

####
#### Main block
####

if ! command -v docker &> /dev/null ; then
    echo "ERR: docker not found"
    exit
fi

ParseOptions $@

BuildDockerImage

if [ $ARG_REUSE -eq 1 ] ; then
    BuildSvsmReuse
else
    BuildSvsmDelete
fi
