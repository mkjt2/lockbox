FROM python:3.11-slim

ARG USERNAME=lockbox
ARG USER_UID=1000
ARG USER_GID=1000
ARG LOCKBOX_PROXY_VERSION=0.1.3

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME

USER $USERNAME
WORKDIR /home/$USERNAME

RUN python -m venv venv
RUN . venv/bin/activate && pip install --no-cache-dir lockbox-proxy==$LOCKBOX_PROXY_VERSION

CMD ["/bin/sh", "-c", ". venv/bin/activate && gunicorn lockbox.app:app --preload -b 0.0.0.0:8000"]
