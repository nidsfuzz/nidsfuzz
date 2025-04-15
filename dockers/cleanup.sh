#!/bin/bash -e

cd "$(dirname "$0")" || exit 1
set -eu

usage() {
    echo "Usage: $0 [--fuzz | --replay]"
    exit 1
}

kill_task() {
  CONTAINER_NAME=$1
  PROCESS_NAME=$2

  if [ -z "$CONTAINER_NAME" ] || [ -z "$PROCESS_NAME" ]; then
    echo "Usage: kill_task <container_name> <process_name>"
    return 1
  fi

  # Find the process inside the container and kill it
  docker exec -it "$CONTAINER_NAME" /bin/bash -c "
    PID=\$(ps aux | grep '[${PROCESS_NAME:0:1}]${PROCESS_NAME:1}' | awk '{print \$2}');
    if [ ! -z \"\$PID\" ]; then
      echo \"Killing process '$PROCESS_NAME' with PID: \$PID inside container '$CONTAINER_NAME'\";
      kill \$PID;
    else
      echo \"Process 'PROCESS_NAME' not found in container '$CONTAINER_NAME'.\";
    fi
  "
}

#######################################
#######################################

COMMAND="--fuzz"
OUI_DIR="fuzz"

# Check the number of parameters
if [[ $# -gt 1 ]]; then
    echo "Error: Too many arguments."
    usage
fi

if [[ $# -eq 1 ]]; then
    case "$1" in
        --fuzz)
            COMMAND="--fuzz"
            OUI_DIR="fuzz"
            ;;
        --replay)
            COMMAND="--replay"
            OUI_DIR="replay"
            ;;
        *)
            echo "Error: Invalid argument '$1'."
            usage
            ;;
    esac
fi

#######################################
#######################################

echo "-------------------"
echo "Stopping docker-compose..."
kill_task "snort3" "snort" || true
kill_task "suricata" "suricata" || true

if [[ "$COMMAND" == "--fuzz" ]]; then
    # Start the fuzzing
    docker compose \
        -f docker-compose/main.yml \
        -f docker-compose/fuzz.yml \
        --env-file docker-compose/config.env \
        stop
elif [[ "$COMMAND" == "--replay" ]]; then
    docker compose \
        -f docker-compose/main.yml \
        -f docker-compose/replay.yml \
        --env-file docker-compose/config.env \
        stop
fi

echo "-------------------"
read -p "Do you want to copy alerts\logs? (Yes): " action
action=$(echo "$action" | tr '[:upper:]' '[:lower:]')
if [[ "$action" != "no" && "$action" != "n" ]]; then
    # Check if the logs directory exists in the current path
    if [ -d ${OUI_DIR} ]; then
      echo "The ${OUI_DIR} directory exists, deleting it..."
      rm -r ${OUI_DIR}
      echo "The ${OUI_DIR} directory has been deleted."
    fi
    # Copying the logs of each module
    echo "Copying the logs of each module..."
    mkdir -p ${PWD}/${OUI_DIR}/initiator/ && docker cp initiator:/data/log/ ${PWD}/${OUI_DIR}/initiator/
    mkdir -p ${PWD}/${OUI_DIR}/responder/ && docker cp responder:/data/log ${PWD}/${OUI_DIR}/responder/
    mkdir -p ${PWD}/${OUI_DIR}/snort3/ && docker cp snort3:/data/log/ ${PWD}/${OUI_DIR}/snort3/
    mkdir -p ${PWD}/${OUI_DIR}/suricata/ && docker cp suricata:/data/log/ ${PWD}/${OUI_DIR}/suricata/
else
    echo "Do not copy alerts\logs"
fi

echo "-------------------"
echo "Cleaning up docker volumes..."
if [[ "$COMMAND" == "--fuzz" ]]; then
    # Start the fuzzing
    docker compose \
        -f docker-compose/main.yml \
        -f docker-compose/fuzz.yml \
        --env-file docker-compose/config.env \
        down -v
elif [[ "$COMMAND" == "--replay" ]]; then
    docker compose \
        -f docker-compose/main.yml \
        -f docker-compose/replay.yml \
        --env-file docker-compose/config.env \
        down -v
    docker volume remove replay || true
fi




