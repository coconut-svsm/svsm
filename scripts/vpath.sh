builtin=`cargo metadata --format-version 1 | jq -r '.packages[] | select(.name == "builtin_macros") | .targets[].src_path'`
verus=`dirname $builtin`/../../../
verus=`realpath $verus`
export VERUS_PATH=$verus
