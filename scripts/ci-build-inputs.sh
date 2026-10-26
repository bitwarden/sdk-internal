# shellcheck shell=bash
# Shared by ci-mark-changed-files.sh and ci-record-build-inputs.sh.
#
# Prints "<hash>\t<path>" for every tracked file that exists in the working tree. The hash is of
# the working-tree content (not the index), so local modifications made before the build count.
list_build_inputs() {
  local paths
  paths=$(mktemp)
  git -c core.quotePath=false ls-files --cached --exclude-standard \
    | grep -vxF -f <(git -c core.quotePath=false ls-files --deleted) > "$paths" || true
  # shellcheck disable=SC2094 # both commands only read the file
  git hash-object --stdin-paths < "$paths" | paste - "$paths"
  rm -f "$paths"
}
