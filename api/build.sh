#!/usr/bin/env bash

set -o errexit

REQUIREMENTS_FILE="${RENDER_REQUIREMENTS_FILE:-requirements.txt}"

if [ ! -f "${REQUIREMENTS_FILE}" ]; then
	echo "Requirements file not found: ${REQUIREMENTS_FILE}"
	exit 1
fi

pip install --upgrade pip
pip install -r "${REQUIREMENTS_FILE}"
python manage.py collectstatic --noinput
