#!/bin/bash
set -euo pipefail
umask 077

# Runs only inside the single explicitly granted, task-owned Go container.
profile=${1:?source profile}
repository=${2:?official repository URL}
release=${3:?release tag}
commit=${4:?source commit}
release_variable=${5:?vendor release environment name}
git_seconds=${6:?Git bound}
generator_seconds=${7:?generator bound}

source_dir=/work/src/$profile
output_dir=/outputs/$profile
mkdir -p "$source_dir" "$output_dir" "$HOME" "$GOMODCACHE" "$GOCACHE" "$GOPATH"
date -u +%FT%TZ > "$output_dir/started-at.txt"
go version > "$output_dir/go-version.txt"
go env -json > "$output_dir/go-environment.json"
git init --quiet "$source_dir"
cd "$source_dir"
git remote add origin "$repository"
timeout --signal=TERM --kill-after=5 "$git_seconds" git -c credential.helper= -c protocol.file.allow=never fetch --depth=1 origin "refs/tags/$release"
test "$(git rev-parse 'FETCH_HEAD^{commit}')" = "$commit"
git checkout --quiet --detach "$commit"
git status --porcelain=v1 --untracked-files=all > "$output_dir/source-before.status"
test ! -s "$output_dir/source-before.status"
git show --no-patch --format=fuller HEAD > "$output_dir/source-commit.txt"
git ls-files --stage > "$output_dir/source-index.txt"
git archive HEAD > "$output_dir/source.tar"
sha256sum "$output_dir/source.tar" > "$output_dir/source-archive.sha256"
awk -F '\t' -v profile="$profile" '$1 == profile { print $2 "  " $3 }' /inputs/source-checks.tsv > "$output_dir/expected-source.sha256"
test "$(wc -l < "$output_dir/expected-source.sha256")" -eq 5
sha256sum --check "$output_dir/expected-source.sha256" > "$output_dir/source-checks-before.txt"

# The vendor generator reads the real clean Git commit and commit time.
# Apply RELEASE to that generator itself, not only to a later build process.
timeout --signal=TERM --kill-after=5 "$generator_seconds" env "$release_variable=RELEASE" go run buildscripts/gen-ldflags.go > "$output_dir/ldflags.txt"
flags=$(cat "$output_dir/ldflags.txt")
mapfile -d '' -t build_arguments < /inputs/build-arguments
printf '%q ' go build "${build_arguments[@]}" -ldflags "$flags" -o "$output_dir/binary" . > "$output_dir/build-command.txt"
printf '\n' >> "$output_dir/build-command.txt"
go build "${build_arguments[@]}" -ldflags "$flags" -o "$output_dir/binary" .
go mod verify > "$output_dir/module-verification.txt"
go version -m "$output_dir/binary" > "$output_dir/go-build-info.txt"
"$output_dir/binary" --version > "$output_dir/version.txt"
grep -F "$release" "$output_dir/version.txt"
grep -F "$commit" "$output_dir/version.txt"
grep -F 'vcs.modified=false' "$output_dir/go-build-info.txt"
grep -F "vcs.revision=$commit" "$output_dir/go-build-info.txt"
sha256sum "$output_dir/binary" > "$output_dir/binary.sha256"
od -An -t u1 -N 20 "$output_dir/binary" > "$output_dir/elf-header.txt"
sha256sum --check "$output_dir/expected-source.sha256" > "$output_dir/source-checks-after.txt"
git status --porcelain=v1 --untracked-files=all > "$output_dir/source-after.status"
test ! -s "$output_dir/source-after.status"
du -sk /work/cache /work/src /outputs > "$output_dir/owned-disk-kib.txt"
date -u +%FT%TZ > "$output_dir/finished-at.txt"
