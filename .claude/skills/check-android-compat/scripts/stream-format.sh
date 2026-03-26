#!/usr/bin/env bash
# stream-format.sh — Reads claude --output-format stream-json from stdin,
# extracts assistant text and tool activity, and prints a clean live view.
#
# Usage:
#   echo "$PROMPT" | claude -p --output-format stream-json --agent ... | ./stream-format.sh

P='\033[38;5;213m' # pink (kirby)
C='\033[38;5;245m' # gray (tools)
B='\033[1m'        # bold
R='\033[0m'        # reset

while IFS= read -r line; do
    type=$(echo "$line" | jq -r '.type // empty' 2>/dev/null)

    case "$type" in
        assistant)
            # Extract text content from assistant message
            text=$(echo "$line" | jq -r '.message.content[]? | select(.type=="text") | .text // empty' 2>/dev/null)
            if [[ -n "$text" ]]; then
                echo -e "${B}${text}${R}"
            fi

            # Show tool use names
            echo "$line" | jq -r '.message.content[]? | select(.type=="tool_use") | .name // empty' 2>/dev/null | while IFS= read -r tool; do
                if [[ -n "$tool" ]]; then
                    input_preview=$(echo "$line" | jq -r ".message.content[]? | select(.type==\"tool_use\" and .name==\"$tool\") | .input | to_entries | map(\"\(.key)=\(.value | tostring)\") | join(\", \")" 2>/dev/null)
                    echo -e "  ${C}⚙ ${tool}${R} ${C}${input_preview}${R}"
                fi
            done
            ;;
        result)
            # Final result
            cost=$(echo "$line" | jq -r '.total_cost_usd // empty' 2>/dev/null)
            turns=$(echo "$line" | jq -r '.num_turns // empty' 2>/dev/null)
            duration=$(echo "$line" | jq -r '.duration_ms // empty' 2>/dev/null)
            if [[ -n "$cost" ]]; then
                duration_s=$((duration / 1000))
                echo ""
                echo -e "${C}--- Done: ${turns} turns, ${duration_s}s, \$${cost} ---${R}"
            fi
            ;;
    esac
done
