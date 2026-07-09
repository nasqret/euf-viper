#!/usr/bin/env bash
#SBATCH --job-name=euf-satsuma-build
#SBATCH --partition=cpu_idle
#SBATCH --cpus-per-task=4
#SBATCH --mem=8G
#SBATCH --time=00:20:00
#SBATCH --output=results/euf-satsuma-build-%j.out
#SBATCH --error=results/euf-satsuma-build-%j.err

set -euo pipefail

ROOT="${SLURM_SUBMIT_DIR:-$PWD}"
SOURCE="$ROOT/third_party/satsuma"
BUILD="$SOURCE/build-release"
CMAKE="${CMAKE:-$ROOT/third_party/cmake-venv/bin/cmake}"

test -f "$SOURCE/CMakeLists.txt"
test -x "$CMAKE"
"$CMAKE" -S "$SOURCE" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release
"$CMAKE" --build "$BUILD" --target satsuma -j "${SLURM_CPUS_PER_TASK:-1}"

git -C "$SOURCE" rev-parse HEAD
sha256sum "$BUILD/satsuma"
