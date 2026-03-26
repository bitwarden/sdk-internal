#!/usr/bin/env bash
set -euo pipefail

# extract-kotlin-api.sh — Extracts the public API surface from generated UniFFI Kotlin bindings.
#
# Usage:
#   ./extract-kotlin-api.sh <kotlin-dir>           Extract API surface from directory
#   ./extract-kotlin-api.sh --diff <old> <new>      Extract and diff two directories
#   ./extract-kotlin-api.sh --test                   Run self-test against fixtures
#
# Output: Sorted, deterministic text representation of the public Kotlin API surface.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEFAULT_KOTLIN_DIR="crates/bitwarden-uniffi/kotlin/sdk/src/main/java/com/bitwarden"

# --- Self-test mode ---
if [[ "${1:-}" == "--test" ]]; then
    FIXTURES_DIR="$SCRIPT_DIR/test-fixtures"
    if [[ ! -d "$FIXTURES_DIR" ]]; then
        echo "ERROR: Test fixtures directory not found: $FIXTURES_DIR" >&2
        exit 1
    fi

    TEMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TEMP_DIR"' EXIT

    BEFORE_DIR="$TEMP_DIR/before/com/bitwarden/test"
    AFTER_DIR="$TEMP_DIR/after/com/bitwarden/test"
    mkdir -p "$BEFORE_DIR" "$AFTER_DIR"
    cp "$FIXTURES_DIR/sample-before.kt" "$BEFORE_DIR/sample.kt"
    cp "$FIXTURES_DIR/sample-after.kt" "$AFTER_DIR/sample.kt"

    "$0" "$TEMP_DIR/before" > "$TEMP_DIR/api-old.txt"
    "$0" "$TEMP_DIR/after" > "$TEMP_DIR/api-new.txt"

    diff -u "$TEMP_DIR/api-old.txt" "$TEMP_DIR/api-new.txt" | tail -n +3 > "$TEMP_DIR/actual-diff.txt" || true

    if diff -q "$TEMP_DIR/actual-diff.txt" <(tail -n +3 "$FIXTURES_DIR/expected-diff.txt") > /dev/null 2>&1; then
        echo "PASS: Self-test passed — extraction and diff match expected output."
        exit 0
    else
        echo "FAIL: Self-test failed — diff does not match expected output." >&2
        echo "" >&2
        echo "=== Expected ===" >&2
        cat "$FIXTURES_DIR/expected-diff.txt" >&2
        echo "" >&2
        echo "=== Actual ===" >&2
        cat "$TEMP_DIR/actual-diff.txt" >&2
        echo "" >&2
        echo "=== Diff of diffs ===" >&2
        diff -u "$FIXTURES_DIR/expected-diff.txt" "$TEMP_DIR/actual-diff.txt" >&2 || true
        exit 1
    fi
fi

# --- Diff mode ---
if [[ "${1:-}" == "--diff" ]]; then
    if [[ $# -lt 3 ]]; then
        echo "Usage: $0 --diff <old-dir> <new-dir>" >&2
        exit 1
    fi
    OLD_DIR="$2"
    NEW_DIR="$3"

    TEMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TEMP_DIR"' EXIT

    "$0" "$OLD_DIR" > "$TEMP_DIR/api-old.txt"
    "$0" "$NEW_DIR" > "$TEMP_DIR/api-new.txt"

    diff -u "$TEMP_DIR/api-old.txt" "$TEMP_DIR/api-new.txt" || true
    exit 0
fi

# --- Extract mode ---
KOTLIN_DIR="${1:-$DEFAULT_KOTLIN_DIR}"

if [[ ! -d "$KOTLIN_DIR" ]]; then
    echo "ERROR: Directory not found: $KOTLIN_DIR" >&2
    exit 1
fi

# Find all Kotlin files and process them
find "$KOTLIN_DIR" -name "*.kt" -type f | sort | while read -r kt_file; do
    awk '
    BEGIN {
        in_data_class = 0
        in_sealed_class = 0
        in_enum_class = 0
        in_interface = 0
        in_sealed_exception = 0
        skip_block = 0
        skip_depth = 0
        brace_depth = 0
        current_package = ""
        class_name = ""
        printed_package = 0
        in_comment = 0
    }

    function extract_name(line, prefix,    tmp) {
        tmp = line
        sub(prefix, "", tmp)
        sub(/[( {:<].*/, "", tmp)
        gsub(/ /, "", tmp)
        return tmp
    }

    function clean_type(t) {
        gsub(/kotlin\./, "", t)
        gsub(/^ +/, "", t)
        gsub(/ +$/, "", t)
        gsub(/,$/, "", t)
        return t
    }

    function print_package() {
        if (current_package != "" && !printed_package) {
            print "PACKAGE " current_package
            print ""
            printed_package = 1
        }
    }

    function count_char(str, ch,    n, i) {
        n = 0
        for (i = 1; i <= length(str); i++) {
            if (substr(str, i, 1) == ch) n++
        }
        return n
    }

    # Track package
    /^package / {
        current_package = $2
        next
    }

    # Skip various non-API lines
    /^import / { next }
    /^@file:/ { next }
    /^\/\// { next }
    /^\/\*/ { in_comment = 1 }
    in_comment && /\*\// { in_comment = 0; next }
    in_comment { next }
    /^ *\*/ && !in_data_class && !in_sealed_class && !in_enum_class && !in_interface && !in_sealed_exception { next }

    # Skip UniFFI boilerplate types
    /^(open )?class RustBuffer/ ||
    /^class RustBufferByReference/ ||
    /^(internal )?open class ForeignBytes/ ||
    /^public interface FfiConverter/ ||
    /^(public )?object FfiConverter/ ||
    /^interface UniffiRustCallStatusErrorHandler/ ||
    /^object UniffiNullRustCallStatusErrorHandler/ ||
    /^internal object UniffiHandleMap/ ||
    /^class InternalException/ ||
    /^object NoHandle/ ||
    /^object UniffiWithHandle/ ||
    /^public object FfiConverterString/ ||
    /^interface Disposable/ ||
    /^inline fun.*Disposable/ ||
    /^(internal )?interface UniffiLib/ ||
    /^(private )?interface UniffiCleaner/ ||
    /^(private )?class (Uniffi|JavaUniffi|AndroidUniffi)/ ||
    /^internal class UniffiRustCallStatus/ ||
    /^internal interface Uniffi/ ||
    /^interface UniffiRustFuture/ ||
    /^internal fun uniffi/ ||
    /^private fun uniffi/ ||
    /^fun uniffi/ {
        skip_block = 1
        skip_depth = 0
        skip_depth += count_char($0, "{")
        skip_depth -= count_char($0, "}")
        if (skip_depth <= 0) { skip_block = 0; skip_depth = 0 }
        next
    }

    # Skip @suppress annotated objects (FfiConverters)
    /^ *\* @suppress/ {
        next
    }

    /^public object FfiConverter/ {
        skip_block = 1
        skip_depth = 0
        skip_depth += count_char($0, "{")
        skip_depth -= count_char($0, "}")
        if (skip_depth <= 0) { skip_block = 0; skip_depth = 0 }
        next
    }

    /^@Structure/ { next }

    # Skip blocks: track brace depth
    skip_block {
        skip_depth += count_char($0, "{")
        skip_depth -= count_char($0, "}")
        if (skip_depth <= 0) { skip_block = 0; skip_depth = 0 }
        next
    }

    # --- Typealias ---
    /^typealias / {
        print_package()
        tmp = $0
        sub(/^typealias /, "", tmp)
        print "TYPEALIAS " tmp
        print ""
        next
    }

    # --- Data class (not inside sealed) ---
    /^data class / && !in_sealed_class {
        if ($0 ~ /FfiConverter/ || $0 ~ /RustBuffer/ || $0 ~ /Uniffi/) next
        class_name = extract_name($0, "^data class ")
        print_package()
        print "DATA_CLASS " class_name
        in_data_class = 1
        data_class_paren_depth = count_char($0, "(") - count_char($0, ")")
        next
    }

    in_data_class {
        data_class_paren_depth += count_char($0, "(")
        data_class_paren_depth -= count_char($0, ")")

        # Extract field: val `name`: Type or val name: Type
        if ($0 ~ /val /) {
            tmp = $0
            # Remove leading whitespace
            gsub(/^ +/, "", tmp)
            # Check if it matches val pattern
            if (tmp ~ /^val /) {
                # Extract field name (remove backticks)
                fname = tmp
                sub(/^val `?/, "", fname)
                sub(/`?:.*/, "", fname)
                gsub(/ /, "", fname)
                # Extract field type
                ftype = tmp
                sub(/^val `?[^:]+`?: */, "", ftype)
                ftype = clean_type(ftype)
                if (fname != "" && ftype != "") {
                    print "  FIELD " fname ": " ftype
                }
            }
        }

        # End of constructor params
        if (data_class_paren_depth <= 0) {
            in_data_class = 0
            print ""
            # Skip the body
            skip_block = 1
            skip_depth = count_char($0, "{") - count_char($0, "}")
            if (skip_depth <= 0) { skip_block = 0; skip_depth = 0 }
        }
        next
    }

    # --- Sealed class (non-exception) ---
    /^sealed class / && $0 !~ /Exception/ && $0 !~ /: kotlin\.Exception/ {
        class_name = extract_name($0, "^sealed class ")
        print_package()
        print "SEALED_CLASS " class_name
        in_sealed_class = 1
        sealed_depth = count_char($0, "{") - count_char($0, "}")
        next
    }

    # --- Sealed interface ---
    /^sealed interface / {
        class_name = extract_name($0, "^sealed interface ")
        print_package()
        print "SEALED_INTERFACE " class_name
        in_sealed_class = 1
        sealed_depth = count_char($0, "{") - count_char($0, "}")
        next
    }

    in_sealed_class {
        sealed_depth += count_char($0, "{")
        sealed_depth -= count_char($0, "}")

        # Data class variant
        if ($0 ~ /data class [A-Z]/) {
            vname = $0
            gsub(/^ +/, "", vname)
            sub(/^data class /, "", vname)
            # Get variant name
            vn = vname
            sub(/\(.*/, "", vn)
            gsub(/ /, "", vn)
            # Get fields
            vf = ""
            if (vname ~ /\(.*\)/) {
                vf = vname
                sub(/^[^(]*\(/, "", vf)
                sub(/\)[^)]*$/, "", vf)
                gsub(/val /, "", vf)
                gsub(/`/, "", vf)
                gsub(/kotlin\./, "", vf)
                gsub(/ +/, " ", vf)
                gsub(/^ /, "", vf)
                gsub(/ $/, "", vf)
            }
            if (vf != "") {
                print "  VARIANT " vn "(" vf ")"
            } else {
                print "  VARIANT " vn
            }
        }

        # Object variant
        if ($0 ~ /object [A-Z]/ && $0 !~ /companion object/ && $0 !~ /FfiConverter/ && $0 !~ /ErrorHandler/) {
            vname = $0
            gsub(/^ +/, "", vname)
            sub(/^object /, "", vname)
            sub(/ .*/, "", vname)
            gsub(/ /, "", vname)
            print "  VARIANT " vname
        }

        if (sealed_depth <= 0) {
            in_sealed_class = 0
            print ""
        }
        next
    }

    # --- Sealed exception class ---
    /^sealed class .*Exception/ || (/^sealed class / && /: kotlin\.Exception/) {
        class_name = extract_name($0, "^sealed class ")
        print_package()
        print "SEALED_EXCEPTION " class_name
        in_sealed_exception = 1
        sealed_exc_depth = count_char($0, "{") - count_char($0, "}")
        next
    }

    in_sealed_exception {
        sealed_exc_depth += count_char($0, "{")
        sealed_exc_depth -= count_char($0, "}")

        # Exception variant: class Foo(message: String) : ParentException(message)
        if ($0 ~ /class [A-Z]/ && $0 !~ /companion/ && $0 !~ /FfiConverter/ && $0 !~ /ErrorHandler/) {
            vname = $0
            gsub(/^ +/, "", vname)
            sub(/^class /, "", vname)
            # Get name
            vn = vname
            sub(/\(.*/, "", vn)
            gsub(/ /, "", vn)
            # Get params
            vp = ""
            if (vname ~ /\([^)]+\)/) {
                vp = vname
                sub(/^[^(]*\(/, "", vp)
                sub(/\).*/, "", vp)
                vp = clean_type(vp)
            }
            if (vp != "") {
                print "  VARIANT " vn "(" vp ")"
            } else {
                print "  VARIANT " vn
            }
        }

        if (sealed_exc_depth <= 0) {
            in_sealed_exception = 0
            print ""
        }
        next
    }

    # --- Enum class ---
    /^enum class / {
        class_name = extract_name($0, "^enum class ")
        print_package()
        print "ENUM " class_name
        in_enum_class = 1
        enum_depth = count_char($0, "{") - count_char($0, "}")
        next
    }

    in_enum_class {
        enum_depth += count_char($0, "{")
        enum_depth -= count_char($0, "}")

        # Enum value: NAME(value), or NAME, or NAME;
        if ($0 ~ /^ +[A-Z][A-Z0-9_]+/ && $0 !~ /companion/) {
            val = $0
            gsub(/^ +/, "", val)
            sub(/\(.*/, "", val)
            sub(/,.*/, "", val)
            sub(/;.*/, "", val)
            gsub(/ /, "", val)
            if (val != "") print "  VALUE " val
        }

        if (enum_depth <= 0) {
            in_enum_class = 0
            print ""
        }
        next
    }

    # --- Interface (client interfaces and callback interfaces) ---
    /^interface [A-Z]/ && $0 !~ /FfiConverter/ && $0 !~ /Uniffi/ && $0 !~ /Disposable/ {
        class_name = extract_name($0, "^interface ")
        if (class_name == "") next
        print_package()
        print "INTERFACE " class_name
        in_interface = 1
        iface_depth = count_char($0, "{") - count_char($0, "}")
        next
    }

    in_interface {
        iface_depth += count_char($0, "{")
        iface_depth -= count_char($0, "}")

        # Suspend fun
        if ($0 ~ /suspend fun /) {
            tmp = $0
            gsub(/^ +/, "", tmp)
            sub(/^suspend fun /, "", tmp)
            # Remove backticks
            gsub(/`/, "", tmp)
            # Normalize kotlin. prefix
            gsub(/kotlin\./, "", tmp)
            print "  SUSPEND_FUN " tmp
        }
        # Regular fun (not override, not companion)
        else if ($0 ~ /fun [a-zA-Z]/ && $0 !~ /companion/ && $0 !~ /override/) {
            tmp = $0
            gsub(/^ +/, "", tmp)
            sub(/^fun /, "", tmp)
            gsub(/`/, "", tmp)
            gsub(/kotlin\./, "", tmp)
            print "  FUN " tmp
        }

        if (iface_depth <= 0) {
            in_interface = 0
            print ""
        }
        next
    }

    # --- Open class (implementing interfaces) ---
    /^open class [A-Z]/ && $0 !~ /RustBuffer/ {
        class_name = extract_name($0, "^open class ")
        # Extract implemented interfaces
        implements = ""
        if ($0 ~ /: /) {
            implements = $0
            sub(/^[^:]*: */, "", implements)
            sub(/ *\{.*/, "", implements)
            # Remove Disposable and AutoCloseable
            gsub(/Disposable, */, "", implements)
            gsub(/AutoCloseable, */, "", implements)
            gsub(/, *$/, "", implements)
            gsub(/^ */, "", implements)
        }
        print_package()
        if (implements != "") {
            print "OPEN_CLASS " class_name " : " implements
        } else {
            print "OPEN_CLASS " class_name
        }
        print ""
        # Skip the implementation body
        skip_block = 1
        skip_depth = count_char($0, "{") - count_char($0, "}")
        if (skip_depth <= 0) { skip_block = 0; skip_depth = 0 }
        next
    }

    ' "$kt_file"
done
