FROM ubuntu:latest
ARG DEBIAN_FRONTEND="noninteractive"
ARG GOVERSION="1.22.0"
ARG ZIGVERSION="0.11.0"

RUN apt update && apt list --upgradable -a && apt upgrade -y
RUN apt update && apt install -y xz-utils software-properties-common cmake make build-essential git curl wget jq sudo procps zsh tar screen ca-certificates procps lsb-release gnupg gnupg2 gpg apt-transport-https python3-pip apt-file attr bash-completion bc bison clang command-not-found dialog dos2unix ed flex gawk gperf htop libresolv-wrapper lld llvm lsof man neofetch neovim rhash tree tshark unbound unzip xxhash openssh-server openssh-client
STOPSIGNAL SIGSTOP
CMD [ "zsh" ]
WORKDIR /root

# Nodejs
RUN curl https://deb.nodesource.com/setup_lts.x | bash && apt install nodejs -y

# Go (golang)
RUN wget -qO- "https://go.dev/dl/go${GOVERSION}.linux-$(dpkg --print-architecture).tar.gz" | tar -C /usr/local -xzv && ln -s /usr/local/go/bin/go /usr/bin/go && ln -s /usr/local/go/bin/gofmt /usr/bin/gofmt

# Install Github CLI (gh)
RUN (wget -q "$(wget -qO- https://api.github.com/repos/cli/cli/releases/latest | grep 'browser_download_url' | grep '.deb' | cut -d \" -f 4 | grep $(dpkg --print-architecture))" -O /tmp/gh.deb && dpkg -i /tmp/gh.deb && rm /tmp/gh.deb) || echo "Fail Install gh"

# Zig
RUN wget -qO- "https://ziglang.org/download/${ZIGVERSION}/zig-linux-$(uname -m)-${ZIGVERSION}.tar.xz" | tar -xvJ -C /usr/local/ && \
  mv -v /usr/local/zig* /usr/local/zig && \
  ln -s /usr/local/zig/zig /usr/bin/zig

ARG USERNAME="devcontainer"
ARG USER_UID="1000"
ARG USER_GID=$USER_UID

# Add non root user and Install oh my zsh
RUN addgroup --gid "${USER_GID}" "${USERNAME}"; useradd --uid "${USER_UID}" --gid "${USER_GID}" --groups sudo -m --shell /usr/bib/zsh "${USERNAME}" -p test
USER $USERNAME
WORKDIR /home/$USERNAME
RUN git clone https://github.com/Sirherobrine23/dotfiles.git dotfiles && cd dotfiles && ./install; cd /home/$USERNAME; rm -rf dotfiles