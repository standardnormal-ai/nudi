#!/bin/bash
# Runs in a fresh verifier box. Only the declared artifact should arrive from the agent box.
mkdir -p /logs/verifier
answer=0.0
leaked=0.0
[ "$(cat /app/answer.txt 2>/dev/null)" = "42" ] && answer=1.0
[ -e /app/scratch.txt ] && leaked=1.0
echo "{\"reward\": $answer, \"undeclared_file_present\": $leaked}" > /logs/verifier/reward.json
