#!/bin/bash

git pull

env EDGENET_REF="$(git rev-parse HEAD)" EDGENET_REPOSITORY="file://$(pwd)" ./bootstrap.sh

