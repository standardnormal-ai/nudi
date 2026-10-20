#!/bin/bash
# Grades /app/answer.txt. A /app/crash_grader file makes the grader exit without a reward.
mkdir -p /logs/verifier
if [ -f /app/crash_grader ]; then
  exit 3
fi
if [ "$(cat /app/answer.txt 2>/dev/null)" = "42" ]; then
  echo '{"reward": 1.0, "answer_ok": 1.0}' > /logs/verifier/reward.json
else
  echo '{"reward": 0.0, "answer_ok": 0.0}' > /logs/verifier/reward.json
fi
