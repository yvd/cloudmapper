#!/bin/bash

# Run the initial entrypoint script
/app/entrypoint.sh prod

# Start cron in the foreground
cron -f &

# Keep the container running
tail -f /dev/null