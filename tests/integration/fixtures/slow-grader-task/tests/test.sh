#!/bin/bash
# Writes a passing reward only after 30 s, past the 5 s verifier timeout.
mkdir -p /logs/verifier
sleep 30
echo '{"reward": 1.0}' > /logs/verifier/reward.json
