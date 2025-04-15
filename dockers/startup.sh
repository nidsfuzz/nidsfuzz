#!/bin/bash -e

cd "$(dirname "$0")" || exit 1
set -eu

usage() {
    echo "Usage: $0 [--fuzz | --replay]"
    exit 1
}

build_image() {
    local image_name="$1"
    local dockerfile="$2"
    local build_context="$3"

    local image_id=$(docker images -q "$image_name")
    if [ -n "$image_id" ]; then
        echo "-------------------"
        echo "Found image: $image_name $image_id"

        read -p "Do you want to rebuild the image? (No): " action
        action=$(echo "$action" | tr '[:upper:]' '[:lower:]')

        if [[ "$action" == "yes" || "$action" == "y" ]]; then
            echo "Deleting ${image_id}"
            docker rmi "${image_id}"
            echo "Building image: $image_name"
            docker build -t "$image_name" -f "$dockerfile" "$build_context"
            echo "Successfully built: $image_name"
        else
            echo "Do not rebuild ${image_name}"
        fi
    else
        echo "-------------------"
        echo "Building image: $image_name"
        docker build -t "$image_name" -f "$dockerfile" "$build_context"
        echo "Successfully built: $image_name"
    fi
}

#######################################
#######################################

COMMAND="--fuzz"
TRAFFIC="fuzz/initiator/log"

if [[ $# -gt 0 ]]; then
    case "$1" in
        --fuzz)
            COMMAND="--fuzz"
            ;;
        --replay)
            COMMAND="--replay"
            shift
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    -traffic)
                        shift
                        if [[ -z "$1" ]]; then
                            echo "Error: Missing value for -traffic."
                            usage
                        fi
                        TRAFFIC="$1"
                        ;;
                    *)
                        echo "Error: Invalid option '$1'."
                        usage
                        ;;
                esac
                shift
            done
            ;;
        *)
            echo "Error: Invalid argument '$1'."
            usage
            ;;
    esac
fi

#######################################
#######################################

# Prepare some essential images, including nidsfuzz, snort3, and suricata
build_image "nids/nidsfuzz" "dockerfile/Dockerfile.nidsfuzz" "../"
build_image "nids/mirror" "dockerfile/Dockerfile.mirror" "."
build_image "nids/suricata" "dockerfile/Dockerfile.suricata.jammy" "."
build_image "nids/snort3" "dockerfile/Dockerfile.snort3.bionic" "."


# Execute different docker-compose commands based on parameters
if [[ "$COMMAND" == "--fuzz" ]]; then
    # Start the fuzzing
    docker compose \
        -f docker-compose/main.yml \
        -f docker-compose/fuzz.yml \
        --env-file docker-compose/config.env \
        up -d
elif [[ "$COMMAND" == "--replay" ]]; then
    docker volume remove replay || true
    docker volume create replay
    docker run --rm -v replay:/replay/ -v ${PWD}/${TRAFFIC}:/data busybox cp -r /data/. /replay/
    docker compose \
        -f docker-compose/main.yml \
        -f docker-compose/replay.yml \
        --env-file docker-compose/config.env \
        up -d
fi




