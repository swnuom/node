#!/bin/bash

env EDGENET_REF="$(git rev-parse HEAD)" EDGENET_REPOSITORY="file://$(pwd)" ./bootstrap.sh

