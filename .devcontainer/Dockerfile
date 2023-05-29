# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.238.0/containers/debian/.devcontainer/base.Dockerfile

# [Choice] Debian version (use bullseye on local arm64/Apple Silicon): bullseye, buster
ARG VARIANT="buster"
FROM mcr.microsoft.com/vscode/devcontainers/base:0-${VARIANT}

# ** [Optional] Uncomment this section to install additional packages. **
# RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
#     && apt-get -y install --no-install-recommends <your-package-list-here>

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends build-essential

WORKDIR /opt
ADD fake-gitconfig /root/.gitconfig
RUN git clone https://github.com/janet-lang/janet.git \
    && cd janet \
    && git revert --no-edit 398833ebe333efa751c52d2fa0f0a940d1d9878b \
    && make \
    && make install
RUN git clone https://github.com/janet-lang/jpm.git  \
    && cd jpm \
    && git checkout 2b9c5db4560fab0ab094a1655499ea96ca7149e6 \
    && janet bootstrap.janet