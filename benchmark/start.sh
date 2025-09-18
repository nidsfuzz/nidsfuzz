#!/bin/bash -e

cd "$(dirname "$0")" || exit 1
set -eu

usage() {
    echo "Usage: $0 [--fuzzing | --replay]"
    exit 1
}

build_image_from_dockerfile() {
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

task="--fuzzing"
replay_dir="fuzzing-results/initiator/log"

# Check if arguments are specified
if [[ $# -gt 0 ]]; then
    case "$1" in  # Check the first argument
        --fuzzing)
            task="--fuzzing"
            ;;
        --replay)
            task="--replay"
            shift  # Remove the first argument

            # Check the remaining arguments
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    -packets)
                        shift
                        if [[ -z "$1" ]]; then
                            echo "Error: Missing value for -traffic."
                            usage
                        fi
                        replay_dir="$1"
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
build_image_from_dockerfile "nidsfuzz/nidsfuzz" "dockerfiles/Dockerfile.nidsfuzz" "../"
build_image_from_dockerfile "nidsfuzz/mirror" "dockerfiles/Dockerfile.mirror" "."
build_image_from_dockerfile "nidsfuzz/suricata" "dockerfiles/Dockerfile.suricata" "."
build_image_from_dockerfile "nidsfuzz/snort3" "dockerfiles/Dockerfile.snort3" "."
build_image_from_dockerfile "nidsfuzz/snort2" "dockerfiles/Dockerfile.snort2" "."


# Execute different docker-compose commands based on parameters
if [[ "$task" == "--fuzzing" ]]; then
    # Start the fuzzing
    docker compose \
        -f docker-compose/typology.yml \
        -f docker-compose/fuzzing.yml \
        --env-file docker-compose/variables.env \
        up -d
elif [[ "$task" == "--replay" ]]; then
    docker volume remove replay || true
    docker volume create replay
    docker run --rm -v replay:/replay/ -v ${PWD}/${replay_dir}/packets.bin:/data/packets.bin -v ${PWD}/${replay_dir}/discrepancies.txt:/data/discrepancies.txt busybox cp -r /data/. /replay/
    docker compose \
        -f docker-compose/typology.yml \
        -f docker-compose/replay.yml \
        --env-file docker-compose/variables.env \
        up -d
fi




