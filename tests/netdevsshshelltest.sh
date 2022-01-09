#!/usr/bin/env bash
source mambaforge/etc/profile.d/conda.sh
netdevpy_python_versions=(netdevpy-3.7 netdevpy-3.8 netdevpy-3.9 netdevpy-3.10)
for netdevpy_python_version in "${netdevpy_python_versions[@]}"; do
    conda activate "${netdevpy_python_version}"
    echo "${netdevpy_python_version} activated"
    python -m tests.netdevpy.testnetdevsshshell
    echo "${netdevpy_python_version} deactivated"
done
