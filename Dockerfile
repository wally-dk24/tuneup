# tuneup — stdlib-only, so the image is just Python + the script.
# RUN-free on purpose: COPY-only Dockerfiles build for any arch without qemu.
FROM python:3.12-alpine
COPY tuneup.py /usr/local/bin/tuneup
# No secrets in the image: state lives in TUNEUP_HOME (default ~/.tuneup),
# mounted at runtime. Tools' credentials stay in the caller's environment,
# never baked in.
USER 1000
ENTRYPOINT ["python3", "/usr/local/bin/tuneup"]
